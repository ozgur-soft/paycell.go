package paycell

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

var (
	REFNO_PREFIX         = "001"
	MERCHANT_CODE        = "9998"
	APPLICATION_NAME     = "PAYCELLTEST"
	APPLICATION_PASSWORD = "PaycellTestPassword"
	APPLICATION_URL      = map[string]string{
		"PROD": "https://tpay.turkcell.com.tr/tpay/provision/services/restful/getCardToken",
		"TEST": "https://tpay-test.turkcell.com.tr/tpay/provision/services/restful/getCardToken",
	}
)

type API struct {
	Mode     string
	MSisdn   string
	ClientIP string
}

type Request struct {
	PaymentMethods struct {
		MSisdn interface{}   `json:"msisdn,omitempty"`
		Header RequestHeader `json:"requestHeader,omitempty"`
	}
	MobilePayment struct {
		MSisdn interface{}   `json:"msisdn,omitempty"`
		EulaID interface{}   `json:"eulaID,omitempty"`
		Header RequestHeader `json:"requestHeader,omitempty"`
	}
	OTP struct {
		MSisdn interface{}   `json:"msisdn,omitempty"`
		Amount interface{}   `json:"amount,omitempty"`
		RefNo  interface{}   `json:"referenceNumber,omitempty"`
		OTP    interface{}   `json:"otp,omitempty"`
		Token  interface{}   `json:"token,omitempty"`
		Header RequestHeader `json:"requestHeader,omitempty"`
	}
	Provision struct {
		MSisdn        interface{}   `json:"msisdn,omitempty"`
		Amount        interface{}   `json:"amount,omitempty"`
		Currency      interface{}   `json:"currency,omitempty"`
		RefNo         interface{}   `json:"referenceNumber,omitempty"`
		PaymentType   interface{}   `json:"paymentType,omitempty"`
		PaymentMethod interface{}   `json:"paymentMethodType,omitempty"`
		MerchantCode  interface{}   `json:"merchantCode,omitempty"`
		Header        RequestHeader `json:"requestHeader,omitempty"`
	}
}

type RequestHeader struct {
	ApplicationName     interface{} `json:"applicationName,omitempty"`
	ApplicationPwd      interface{} `json:"applicationPwd,omitempty"`
	ClientIPAddress     interface{} `json:"clientIPAddress,omitempty"`
	TransactionDateTime interface{} `json:"transactionDateTime,omitempty"`
	TransactionId       interface{} `json:"transactionId,omitempty"`
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
		MobilePayment struct {
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
	MobilePayment struct {
		Header ResponseHeader `json:"responseHeader,omitempty"`
	}
	OTP struct {
		Header     ResponseHeader `json:"responseHeader,omitempty"`
		Token      string         `json:"token,omitempty"`
		ExpireDate string         `json:"expireDate,omitempty"`
		RetryCount string         `json:"remainingRetryCount,omitempty"`
	}
	Provision struct {
		Header    ResponseHeader `json:"responseHeader,omitempty"`
		OrderId   string         `json:"orderId,omitempty"`
		OrderDate string         `json:"reconciliationDate,omitempty"`
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

func (api *API) GetPaymentMethods() (response Response) {
	apiurl := APPLICATION_URL[api.Mode] + "/getPaymentMethods/"
	request := new(Request)
	request.PaymentMethods.MSisdn = api.MSisdn
	request.PaymentMethods.Header.ClientIPAddress = api.ClientIP
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
	pretty, _ := json.MarshalIndent(response.PaymentMethods, " ", "\t")
	fmt.Println(string(pretty))
	return response
}

func (api *API) OpenMobilePayment(eula interface{}) (response Response) {
	apiurl := APPLICATION_URL[api.Mode] + "/openMobilePayment/"
	request := new(Request)
	if eula != nil {
		request.MobilePayment.EulaID = eula
	}
	request.MobilePayment.MSisdn = api.MSisdn
	request.MobilePayment.Header.ClientIPAddress = api.ClientIP
	request.MobilePayment.Header.ApplicationName = APPLICATION_NAME
	request.MobilePayment.Header.ApplicationPwd = APPLICATION_PASSWORD
	request.MobilePayment.Header.TransactionDateTime = strings.ReplaceAll(time.Now().Format("20060102150405.000"), ".", "")
	request.MobilePayment.Header.TransactionId = Random(20)
	contactdata, _ := json.Marshal(request.MobilePayment)
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
	decoder.Decode(&response.MobilePayment)
	pretty, _ := json.MarshalIndent(response.MobilePayment, " ", "\t")
	fmt.Println(string(pretty))
	return response
}

func (api *API) SendOTP(amount interface{}) (response Response) {
	apiurl := APPLICATION_URL[api.Mode] + "/sendOTP/"
	request := new(Request)
	if amount != nil {
		request.OTP.Amount = amount
	}
	request.OTP.MSisdn = api.MSisdn
	request.OTP.Header.ClientIPAddress = api.ClientIP
	request.OTP.Header.ApplicationName = APPLICATION_NAME
	request.OTP.Header.ApplicationPwd = APPLICATION_PASSWORD
	request.OTP.Header.TransactionDateTime = strings.ReplaceAll(time.Now().Format("20060102150405.000"), ".", "")
	request.OTP.Header.TransactionId = Random(20)
	request.OTP.RefNo = Random(20)
	contactdata, _ := json.Marshal(request.OTP)
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
	decoder.Decode(&response.OTP)
	pretty, _ := json.MarshalIndent(response.OTP, " ", "\t")
	fmt.Println(string(pretty))
	return response
}

func (api *API) ValidateOTP(token, otp, amount interface{}) (response Response) {
	apiurl := APPLICATION_URL[api.Mode] + "/validateOTP/"
	request := new(Request)
	if token != nil {
		request.OTP.Token = token
	}
	if otp != nil {
		request.OTP.OTP = otp
	}
	if amount != nil {
		request.OTP.Amount = amount
	}
	request.OTP.MSisdn = api.MSisdn
	request.OTP.Header.ClientIPAddress = api.ClientIP
	request.OTP.Header.ApplicationName = APPLICATION_NAME
	request.OTP.Header.ApplicationPwd = APPLICATION_PASSWORD
	request.OTP.Header.TransactionDateTime = strings.ReplaceAll(time.Now().Format("20060102150405.000"), ".", "")
	request.OTP.Header.TransactionId = Random(20)
	request.OTP.RefNo = Random(20)
	contactdata, _ := json.Marshal(request.OTP)
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
	decoder.Decode(&response.OTP)
	pretty, _ := json.MarshalIndent(response.OTP, " ", "\t")
	fmt.Println(string(pretty))
	return response
}

func (api *API) MobilePayment(amount, currency interface{}) (response Response) {
	apiurl := APPLICATION_URL[api.Mode] + "/provisionAll/"
	request := new(Request)
	if amount != nil {
		request.Provision.Amount = amount
	}
	if currency != nil {
		request.Provision.Currency = currency
	}
	request.Provision.PaymentType = "SALE"
	request.Provision.PaymentMethod = "MOBILE_PAYMENT"
	request.Provision.MSisdn = api.MSisdn
	request.Provision.MerchantCode = MERCHANT_CODE
	request.Provision.Header.ClientIPAddress = api.ClientIP
	request.Provision.Header.ApplicationName = APPLICATION_NAME
	request.Provision.Header.ApplicationPwd = APPLICATION_PASSWORD
	request.Provision.Header.TransactionDateTime = strings.ReplaceAll(time.Now().Format("20060102150405.000"), ".", "")
	request.Provision.Header.TransactionId = Random(20)
	request.Provision.RefNo = REFNO_PREFIX + fmt.Sprintf("%v", request.Provision.Header.TransactionDateTime)
	contactdata, _ := json.Marshal(request.Provision)
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
	decoder.Decode(&response.Provision)
	pretty, _ := json.MarshalIndent(response.Provision, " ", "\t")
	fmt.Println(string(pretty))
	return response
}
