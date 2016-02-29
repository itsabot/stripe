package stripe

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"

	"golang.org/x/crypto/bcrypt"

	"github.com/itsabot/abot/core"
	"github.com/itsabot/abot/shared/datatypes"
	"github.com/itsabot/abot/shared/interface/payment"
	"github.com/itsabot/abot/shared/interface/payment/driver"
	"github.com/itsabot/abot/shared/pkg"
	"github.com/jmoiron/sqlx"
	"github.com/labstack/echo"
	"github.com/labstack/gommon/log"
	"github.com/stripe/stripe-go"
	"github.com/stripe/stripe-go/card"
	"github.com/stripe/stripe-go/client"
	"github.com/stripe/stripe-go/customer"
)

type drv struct{}

func (d *drv) Open(db *sqlx.DB, e *echo.Echo, name string) (driver.Conn, error) {
	sc := &client.API{}
	sc.Init(name, nil)
	hm := dt.NewHandlerMap([]dt.RouteHandler{
		{
			Path:    "/api/cards",
			Method:  echo.GET,
			Handler: handlerAPICardSubmit,
		},
		{
			Path:    "/api/cards",
			Method:  echo.DELETE,
			Handler: handlerAPICardDelete,
		},
	})
	hm.AddRoutes("stripe", e)
	return &conn{db: db, client: sc}, nil
}

func init() {
	payment.Register("stripe", &drv{})
}

type conn struct {
	db     *sqlx.DB
	client *client.API
}

func (c *conn) RegisterUser(user *dt.User) error {
	customerParams := &stripe.CustomerParams{Email: user.Email}
	cust, err := customer.New(customerParams)
	if err != nil {
		var js struct {
			Message string
		}
		err = json.Unmarshal([]byte(err.Error()), &js)
		if err != nil {
			return err
		}
		return errors.New(js.Message)
	}
	stripeCustomerID := cust.ID
	q := `UPDATE users SET paymentserviceid=$1 WHERE id=$2`
	_, err = c.db.Exec(q, stripeCustomerID, user.ID)
	return err
}

func (c *conn) SaveCard(p *dt.CardParams, user *dt.User) (uint64, error) {
	hZip, err := bcrypt.GenerateFromPassword([]byte(p.AddressZip[:5]), 10)
	if err != nil {
		return 0, err
	}
	var userStripeID string
	q := `SELECT paymentserviceid FROM users WHERE id=$1`
	if err = c.db.Get(&userStripeID, q, user.ID); err != nil {
		return 0, err
	}
	_, err = c.client.Cards.New(&stripe.CardParams{
		Customer: userStripeID,
		Token:    p.ServiceToken,
	})
	if err != nil {
		return 0, err
	}
	var cardID uint64
	q = `INSERT INTO cards
	     (userid, last4, cardholdername, expmonth, expyear, brand,
	        stripeid, zip5hash)
	     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	     RETURNING id`
	row := c.db.QueryRowx(q, user.ID, p.Last4, p.CardholderName, p.ExpMonth,
		p.ExpYear, p.Brand, p.ServiceToken, hZip)
	err = row.Scan(&cardID)
	if err != nil {
		return 0, err
	}
	return cardID, nil
}

func (c *conn) ChargeCard(cardID uint64, amountInCents uint64,
	isoCurrency string) error {

	var tmp struct {
		ServiceToken string
		UserID       uint64
	}
	q := `SELECT servicetoken, userid FROM cards WHERE id=$1`
	if err := c.db.Get(&tmp, q, cardID); err != nil {
		return err
	}
	var serviceCustomerID string
	q = `SELECT paymentserviceid FROM users WHERE id=$1`
	if err := c.db.Get(&serviceCustomerID, q, tmp.UserID); err != nil {
		return err
	}
	sp, err := stripe.SourceParamsFor(tmp.ServiceToken)
	if err != nil {
		return err
	}
	_, err = c.client.Charges.New(&stripe.ChargeParams{
		Amount:   amountInCents,
		Currency: stripe.Currency(isoCurrency),
		Customer: serviceCustomerID,
		Source:   sp,
	})
	return err
}

func (c *conn) Close() error {
	return nil
}

// handlerAPICardSubmit creates a new credit card via Stripe. As little
// information as possible is kept on the server to protect the users. Card
// details like the card number never touch the server.
func handlerAPICardSubmit(c *echo.Context) error {
	db, err := pkg.ConnectDB()
	if err != nil {
		return core.JSONError(err)
	}
	var req struct {
		StripeToken    string
		CardholderName string
		Last4          string
		Brand          string
		ExpMonth       int
		ExpYear        int
		AddressZip     string
		UserID         int
	}
	if err := c.Bind(&req); err != nil {
		return core.JSONError(err)
	}
	hZip, err := bcrypt.GenerateFromPassword([]byte(req.AddressZip[:5]), 10)
	if err != nil {
		return core.JSONError(err)
	}
	log.Debug("submitting card for user", req.UserID)
	var userStripeID string
	q := `SELECT stripecustomerid FROM users WHERE id=$1`
	if err := db.Get(&userStripeID, q, req.UserID); err != nil {
		return core.JSONError(err)
	}
	stripe.Key = os.Getenv("STRIPE_ACCESS_TOKEN")
	cd, err := card.New(&stripe.CardParams{
		Customer: userStripeID,
		Token:    req.StripeToken,
	})
	if err != nil {
		return core.JSONError(err)
	}
	var crd struct{ ID int }
	q = `
		INSERT INTO cards
		(userid, last4, cardholdername, expmonth, expyear, brand,
			stripeid, zip5hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id`
	row := db.QueryRowx(q, req.UserID, req.Last4, req.CardholderName,
		req.ExpMonth, req.ExpYear, req.Brand, cd.ID, hZip)
	err = row.Scan(&crd.ID)
	if err != nil {
		return core.JSONError(err)
	}
	if err = c.JSON(http.StatusOK, crd); err != nil {
		return core.JSONError(err)
	}
	return nil
}

func handlerAPICardDelete(c *echo.Context) error {
	db, err := pkg.ConnectDB()
	if err != nil {
		return core.JSONError(err)
	}
	var req struct {
		ID     uint64
		UserID uint64
	}
	if err = c.Bind(&req); err != nil {
		return core.JSONError(err)
	}
	q := `SELECT stripeid FROM cards WHERE id=$1`
	var crd dt.Card
	if err = db.Get(&crd, q, req.ID); err != nil {
		log.Debug("couldn't find stripeid", req.ID)
		return core.JSONError(err)
	}
	q = `DELETE FROM cards WHERE id=$1 AND userid=$2`
	if _, err = db.Exec(q, req.ID, req.UserID); err != nil {
		log.Debug("couldn't find card", req.ID, req.UserID)
		return core.JSONError(err)
	}
	q = `SELECT stripecustomerid FROM users WHERE id=$1`
	var user dt.User
	if err = db.Get(&user, q, req.UserID); err != nil {
		log.Debug("couldn't find stripecustomerid", req.UserID)
		return core.JSONError(err)
	}
	_, err = card.Del(crd.ServiceToken, &stripe.CardParams{
		Customer: user.PaymentServiceID,
	})
	if err != nil {
		log.Debug("couldn't delete stripe card", crd.ServiceToken,
			user.PaymentServiceID)
		return core.JSONError(err)
	}
	err = c.JSON(http.StatusOK, nil)
	if err != nil {
		return core.JSONError(err)
	}
	return nil
}
