package stripe

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"

	"golang.org/x/crypto/bcrypt"

	"github.com/itsabot/abot/shared/datatypes"
	"github.com/labstack/echo"
	"github.com/labstack/gommon/log"
	"github.com/stripe/stripe-go"
	"github.com/stripe/stripe-go/card"
	"github.com/stripe/stripe-go/customer"
)

func init() {
	stripe.Key = os.Getenv("STRIPE_ACCESS_TOKEN")
}

func CreateUser() {
	customerParams := &stripe.CustomerParams{Email: req.Email}
	cust, err := customer.New(customerParams)
	if err != nil {
		var js struct {
			Message string
		}
		err = json.Unmarshal([]byte(err.Error()), &js)
		if err != nil {
			return jsonError(err)
		}
		return jsonError(errors.New(js.Message))
	}
	stripeCustomerID := cust.ID
}

// handlerAPICardSubmit creates a new credit card via Stripe. As little
// information as possible is kept on the server to protect the users. Card
// details like the card number never touch the server.
func handlerAPICardSubmit(c *echo.Context) error {
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
		return jsonError(err)
	}
	hZip, err := bcrypt.GenerateFromPassword([]byte(req.AddressZip[:5]), 10)
	if err != nil {
		return jsonError(err)
	}
	log.Debug("submitting card for user", req.UserID)
	var userStripeID string
	q := `SELECT stripecustomerid FROM users WHERE id=$1`
	if err := db.Get(&userStripeID, q, req.UserID); err != nil {
		return jsonError(err)
	}
	stripe.Key = os.Getenv("STRIPE_ACCESS_TOKEN")
	cd, err := card.New(&stripe.CardParams{
		Customer: userStripeID,
		Token:    req.StripeToken,
	})
	if err != nil {
		return jsonError(err)
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
		return jsonError(err)
	}
	if err = c.JSON(http.StatusOK, crd); err != nil {
		return jsonError(err)
	}
	return nil
}

func handlerAPICardDelete(c *echo.Context) error {
	var req struct {
		ID     uint64
		UserID uint64
	}
	if err := c.Bind(&req); err != nil {
		return jsonError(err)
	}
	q := `SELECT stripeid FROM cards WHERE id=$1`
	var crd dt.Card
	if err := db.Get(&crd, q, req.ID); err != nil {
		log.Debug("couldn't find stripeid", req.ID)
		return jsonError(err)
	}
	q = `DELETE FROM cards WHERE id=$1 AND userid=$2`
	if _, err := db.Exec(q, req.ID, req.UserID); err != nil {
		log.Debug("couldn't find card", req.ID, req.UserID)
		return jsonError(err)
	}
	q = `SELECT stripecustomerid FROM users WHERE id=$1`
	var user dt.User
	if err := db.Get(&user, q, req.UserID); err != nil {
		log.Debug("couldn't find stripecustomerid", req.UserID)
		return jsonError(err)
	}
	_, err := card.Del(crd.StripeID, &stripe.CardParams{
		Customer: user.StripeCustomerID,
	})
	if err != nil {
		log.Debug("couldn't delete stripe card", crd.StripeID,
			user.StripeCustomerID)
		return jsonError(err)
	}
	err = c.JSON(http.StatusOK, nil)
	if err != nil {
		return jsonError(err)
	}
	return nil
}
