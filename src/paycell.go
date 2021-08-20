package paycell

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"
)

var (
	MERCHANT_CODE        = "9998"
	SECURE_CODE          = "PAYCELL12345"
	TERMINAL_CODE        = "12345"
	APPLICATION_NAME     = "PAYCELLTEST"
	APPLICATION_PASSWORD = "PaycellTestPassword"
	APPLICATION_URL      = map[string]string{
		"PROD": "https://tpay.turkcell.com.tr/tpay/provision/services/restful/getCardToken",
		"TEST": "https://tpay-test.turkcell.com.tr/tpay/provision/services/restful/getCardToken",
	}
)

type API struct {
	Mode string
}

type Request struct {
	PaymentMethods struct {
		MSisdn string        `json:"msisdn,omitempty"`
		Header RequestHeader `json:"requestHeader,omitempty"`
	}
}

type RequestHeader struct {
	ApplicationName     string `json:"applicationName,omitempty"`
	ApplicationPwd      string `json:"applicationPwd,omitempty"`
	ClientIPAddress     string `json:"clientIPAddress,omitempty"`
	TransactionDateTime string `json:"transactionDateTime,omitempty"`
	TransactionId       string `json:"transactionId,omitempty"`
}

type Response struct {
	PaymentMethods struct {
		Header   ResponseHeader `json:"responseHeader,omitempty"`
		EulaID   string         `json:"eulaID,omitempty"`
		CardList []struct {
			CardBrand         string `json:"cardBrand,omitempty"`
			CardId            string `json:"cardId,omitempty"`
			CardType          string `json:"cardType,omitempty"`
			MaskedCardNo      string `json:"maskedCardNo,omitempty"`
			Alias             string `json:"alias,omitempty"`
			ActivationDate    string `json:"activationDate,omitempty"`
			IsDefault         bool   `json:"isDefault,omitempty"`
			IsExpired         bool   `json:"isExpired,omitempty"`
			ShowEulaId        bool   `json:"showEulaId,omitempty"`
			IsThreeDValidated bool   `json:"isThreeDValidated,omitempty"`
			IsOTPValidated    bool   `json:"isOTPValidated,omitempty"`
		} `json:"cardList,omitempty"`
		MobilePayment []struct {
			EulaId         string `json:"eulaId,omitempty"`
			EulaUrl        string `json:"eulaUrl,omitempty"`
			SignedEulaId   string `json:"signedEulaId,omitempty"`
			StatementDate  string `json:"statementDate,omitempty"`
			Limit          string `json:"limit,omitempty"`
			MaxLimit       string `json:"maxLimit,omitempty"`
			RemainingLimit string `json:"remainingLimit,omitempty"`
			IsDcbOpen      bool   `json:"isDcbOpen,omitempty"`
			IsEulaExpired  bool   `json:"isEulaExpired,omitempty"`
		} `json:"mobilePayment,omitempty"`
	}
}

type ResponseHeader struct {
	ResponseCode        string `json:"responseCode,omitempty"`
	ResponseDescription string `json:"responseDescription,omitempty"`
	ResponseDateTime    string `json:"responseDateTime,omitempty"`
	TransactionId       string `json:"transactionId,omitempty"`
}

func Random(n int) string {
	const alphanum = "0123456789"
	var bytes = make([]byte, n)
	rand.Read(bytes)
	for i, b := range bytes {
		bytes[i] = alphanum[b%byte(len(alphanum))]
	}
	return string(bytes)
}

func (api *API) GetPaymentMethods(request *Request) (response Response) {
	apiurl := APPLICATION_URL[api.Mode] + "/getPaymentMethods/"
	request.PaymentMethods.Header.ApplicationName = APPLICATION_NAME
	request.PaymentMethods.Header.ApplicationPwd = APPLICATION_PASSWORD
	request.PaymentMethods.Header.TransactionDateTime = strings.ReplaceAll(time.Now().Format("20060102150405.000"), ".", "")
	request.PaymentMethods.Header.TransactionId = Random(20)
	contactdata, _ := json.Marshal(request.PaymentMethods)
	cli := new(http.Client)
	req, err := http.NewRequest("POST", apiurl, bytes.NewReader(contactdata))
	if err != nil {
		log.Println(err)
		return response
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := cli.Do(req)
	if err != nil {
		log.Println(err)
		return response
	}
	defer res.Body.Close()
	decoder := json.NewDecoder(res.Body)
	decoder.UseNumber()
	decoder.Decode(&response.PaymentMethods)
	return response
}
