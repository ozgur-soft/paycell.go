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
	Application = "PAYCELLTEST"
	RefPrefix   = "001"
	Merchant    = "9998"
	Password    = "PaycellTestPassword"
	Endpoint    = map[string]string{
		"PROD": "https://tpay.turkcell.com.tr/tpay/provision/services/restful/getCardToken",
		"TEST": "https://tpay-test.turkcell.com.tr/tpay/provision/services/restful/getCardToken",
	}
)

type API struct {
	Mode     string
	MSisdn   string
	ClientIP string
	Amount   string
	Currency string
}

type Request struct {
	PaymentMethods struct {
		MSisdn string        `json:"msisdn,omitempty"`
		Header RequestHeader `json:"requestHeader,omitempty"`
	}
	MobilePayment struct {
		MSisdn string        `json:"msisdn,omitempty"`
		EulaID string        `json:"eulaID,omitempty"`
		Header RequestHeader `json:"requestHeader,omitempty"`
	}
	OTP struct {
		MSisdn string        `json:"msisdn,omitempty"`
		Amount string        `json:"amount,omitempty"`
		RefNo  string        `json:"referenceNumber,omitempty"`
		OTP    string        `json:"otp,omitempty"`
		Token  string        `json:"token,omitempty"`
		Header RequestHeader `json:"requestHeader,omitempty"`
	}
	Provision struct {
		MSisdn        string        `json:"msisdn,omitempty"`
		MerchantCode  string        `json:"merchantCode,omitempty"`
		CardId        string        `json:"cardId,omitempty"`
		CardToken     string        `json:"cardToken,omitempty"`
		RefNo         string        `json:"referenceNumber,omitempty"`
		OriginalRefNo string        `json:"originalReferenceNumber,omitempty"`
		Amount        string        `json:"amount,omitempty"`
		PointAmount   string        `json:"pointAmount,omitempty"`
		Currency      string        `json:"currency,omitempty"`
		Installment   string        `json:"installmentCount,omitempty"`
		PaymentType   string        `json:"paymentType,omitempty"`
		AcquirerBank  string        `json:"acquirerBankCode,omitempty"`
		SessionId     string        `json:"threeDSessionId,omitempty"`
		Pin           string        `json:"pin,omitempty"`
		Header        RequestHeader `json:"requestHeader,omitempty"`
	}
	Reverse struct {
		MSisdn        string        `json:"msisdn,omitempty"`
		MerchantCode  string        `json:"merchantCode,omitempty"`
		RefNo         string        `json:"referenceNumber,omitempty"`
		OriginalRefNo string        `json:"originalReferenceNumber,omitempty"`
		Header        RequestHeader `json:"requestHeader,omitempty"`
	}
	Refund struct {
		MSisdn        string        `json:"msisdn,omitempty"`
		MerchantCode  string        `json:"merchantCode,omitempty"`
		Amount        string        `json:"amount,omitempty"`
		RefNo         string        `json:"referenceNumber,omitempty"`
		OriginalRefNo string        `json:"originalReferenceNumber,omitempty"`
		Header        RequestHeader `json:"requestHeader,omitempty"`
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
		MobilePayment *struct {
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
		Header       ResponseHeader `json:"responseHeader,omitempty"`
		OrderId      string         `json:"orderId,omitempty"`
		OrderDate    string         `json:"reconciliationDate,omitempty"`
		ApprovalCode string         `json:"approvalCodeo,omitempty"`
		AcquirerBank string         `json:"acquirerBankCode,omitempty"`
		IssuerBank   string         `json:"issuerBankCode,omitempty"`
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
	apiurl := Endpoint[api.Mode] + "/getPaymentMethods/"
	request := new(Request)
	request.PaymentMethods.MSisdn = api.MSisdn
	request.PaymentMethods.Header.ClientIPAddress = api.ClientIP
	request.PaymentMethods.Header.ApplicationName = Application
	request.PaymentMethods.Header.ApplicationPwd = Password
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
	apiurl := Endpoint[api.Mode] + "/openMobilePayment/"
	request := new(Request)
	request.MobilePayment.Header.ClientIPAddress = api.ClientIP
	request.MobilePayment.Header.ApplicationName = Application
	request.MobilePayment.Header.ApplicationPwd = Password
	request.MobilePayment.Header.TransactionDateTime = strings.ReplaceAll(time.Now().Format("20060102150405.000"), ".", "")
	request.MobilePayment.Header.TransactionId = Random(20)
	request.MobilePayment.MSisdn = api.MSisdn
	if eula != nil {
		request.MobilePayment.EulaID = eula
	}
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

func (api *API) SendOTP() (response Response) {
	apiurl := Endpoint[api.Mode] + "/sendOTP/"
	request := new(Request)
	request.OTP.Header.ClientIPAddress = api.ClientIP
	request.OTP.Header.ApplicationName = Application
	request.OTP.Header.ApplicationPwd = Password
	request.OTP.Header.TransactionDateTime = strings.ReplaceAll(time.Now().Format("20060102150405.000"), ".", "")
	request.OTP.Header.TransactionId = Random(20)
	request.OTP.MSisdn = api.MSisdn
	request.OTP.RefNo = Random(20)
	request.OTP.Amount = api.Amount
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

func (api *API) ValidateOTP(token, otp interface{}) (response Response) {
	apiurl := Endpoint[api.Mode] + "/validateOTP/"
	request := new(Request)
	request.OTP.Header.ClientIPAddress = api.ClientIP
	request.OTP.Header.ApplicationName = Application
	request.OTP.Header.ApplicationPwd = Password
	request.OTP.Header.TransactionDateTime = strings.ReplaceAll(time.Now().Format("20060102150405.000"), ".", "")
	request.OTP.Header.TransactionId = Random(20)
	request.OTP.MSisdn = api.MSisdn
	request.OTP.RefNo = Random(20)
	request.OTP.Amount = api.Amount
	if token != nil {
		request.OTP.Token = token
	}
	if otp != nil {
		request.OTP.OTP = otp
	}
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

func (api *API) MobilePayment() (response Response) {
	apiurl := Endpoint[api.Mode] + "/provisionAll/"
	request := new(Request)
	request.Provision.Header.ClientIPAddress = api.ClientIP
	request.Provision.Header.ApplicationName = Application
	request.Provision.Header.ApplicationPwd = Password
	request.Provision.Header.TransactionDateTime = strings.ReplaceAll(time.Now().Format("20060102150405.000"), ".", "")
	request.Provision.Header.TransactionId = Random(20)
	request.Provision.MSisdn = api.MSisdn
	request.Provision.MerchantCode = Merchant
	request.Provision.RefNo = RefPrefix + fmt.Sprintf("%v", request.Provision.Header.TransactionDateTime)
	request.Provision.Amount = api.Amount
	request.Provision.Currency = api.Currency
	request.Provision.PaymentType = "SALE"
	request.Provision.PaymentMethod = "MOBILE_PAYMENT"
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
