package paycell

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

var (
	Application = "PAYCELLTEST"
	Password    = "PaycellTestPassword"
	StoreKey    = "PAYCELL12345"
	Merchant    = "9998"
	EulaID      = "17"
	Prefix      = "666"
	Endpoint    = map[string]string{
		"PROD":       "https://tpay.turkcell.com.tr/tpay/provision/services/restful/getCardToken",
		"TEST":       "https://tpay-test.turkcell.com.tr/tpay/provision/services/restful/getCardToken",
		"PROD_TOKEN": "https://epayment.turkcell.com.tr/paymentmanagement/rest/getCardTokenSecure",
		"PROD_FORM":  "https://epayment.turkcell.com.tr/paymentmanagement/rest/threeDSecure",
		"TEST_TOKEN": "https://omccstb.turkcell.com.tr/paymentmanagement/rest/getCardTokenSecure",
		"TEST_FORM":  "https://omccstb.turkcell.com.tr/paymentmanagement/rest/threeDSecure",
	}
)

type any = interface{}

type API struct {
	Mode     string
	MSisdn   string
	ClientIP string
	Amount   string
	Currency string
}

type Request struct {
	CardToken struct {
		Header     RequestHeader `json:"header,omitempty"`
		CardNumber any           `json:"creditCardNo,omitempty"`
		CardMonth  any           `json:"expireDateMonth,omitempty"`
		CardYear   any           `json:"expireDateYear,omitempty"`
		CardCode   any           `json:"cvcNo,omitempty"`
		HashData   any           `json:"hashData,omitempty"`
	}
	Provision struct {
		Header        RequestHeader `json:"requestHeader,omitempty"`
		MSisdn        any           `json:"msisdn,omitempty"`
		MerchantCode  any           `json:"merchantCode,omitempty"`
		CardId        any           `json:"cardId,omitempty"`
		CardToken     any           `json:"cardToken,omitempty"`
		RefNo         any           `json:"referenceNumber,omitempty"`
		OriginalRefNo any           `json:"originalReferenceNumber,omitempty"`
		Amount        any           `json:"amount,omitempty"`
		PointAmount   any           `json:"pointAmount,omitempty"`
		Currency      any           `json:"currency,omitempty"`
		Installment   any           `json:"installmentCount,omitempty"`
		PaymentType   any           `json:"paymentType,omitempty"`
		AcquirerBank  any           `json:"acquirerBankCode,omitempty"`
		ThreeDSession any           `json:"threeDSessionId,omitempty"`
		Pin           any           `json:"pin,omitempty"`
	}
	Refund struct {
		Header        RequestHeader `json:"requestHeader,omitempty"`
		MSisdn        any           `json:"msisdn,omitempty"`
		MerchantCode  any           `json:"merchantCode,omitempty"`
		Amount        any           `json:"amount,omitempty"`
		Currency      any           `json:"currency,omitempty"`
		RefNo         any           `json:"referenceNumber,omitempty"`
		OriginalRefNo any           `json:"originalReferenceNumber,omitempty"`
	}
	Reverse struct {
		Header        RequestHeader `json:"requestHeader,omitempty"`
		MSisdn        any           `json:"msisdn,omitempty"`
		MerchantCode  any           `json:"merchantCode,omitempty"`
		RefNo         any           `json:"referenceNumber,omitempty"`
		OriginalRefNo any           `json:"originalReferenceNumber,omitempty"`
	}
	ThreeDSession struct {
		Header       RequestHeader `json:"requestHeader,omitempty"`
		MSisdn       any           `json:"msisdn,omitempty"`
		MerchantCode any           `json:"merchantCode,omitempty"`
		CardId       any           `json:"cardId,omitempty"`
		CardToken    any           `json:"cardToken,omitempty"`
		Installment  any           `json:"installmentCount,omitempty"`
		Amount       any           `json:"amount,omitempty"`
		Currency     any           `json:"currency,omitempty"`
		RefNo        any           `json:"referenceNumber,omitempty"`
		Target       any           `json:"target,omitempty"`
		Transaction  any           `json:"transactionType,omitempty"`
	}
	ThreeDResult struct {
		Header        RequestHeader `json:"requestHeader,omitempty"`
		MSisdn        any           `json:"msisdn,omitempty"`
		MerchantCode  any           `json:"merchantCode,omitempty"`
		RefNo         any           `json:"referenceNumber,omitempty"`
		ThreeDSession any           `json:"threeDSessionId,omitempty"`
	}
	ThreeDForm struct {
		ThreeDSession  any `form:"threeDSessionId,omitempty"`
		CallbackUrl    any `form:"callbackurl,omitempty"`
		IsPoint        any `form:"isPoint,omitempty"`
		IsPost3DResult any `form:"isPost3DResult,omitempty"`
	}
	PaymentMethods struct {
		Header RequestHeader `json:"requestHeader,omitempty"`
		MSisdn any           `json:"msisdn,omitempty"`
	}
	MobilePayment struct {
		Header RequestHeader `json:"requestHeader,omitempty"`
		MSisdn any           `json:"msisdn,omitempty"`
		EulaID any           `json:"eulaID,omitempty"`
	}
	OTP struct {
		Header   RequestHeader `json:"requestHeader,omitempty"`
		MSisdn   any           `json:"msisdn,omitempty"`
		Amount   any           `json:"amount,omitempty"`
		Currency any           `json:"currency,omitempty"`
		RefNo    any           `json:"referenceNumber,omitempty"`
		OTP      any           `json:"otp,omitempty"`
		Token    any           `json:"token,omitempty"`
	}
}

type Response struct {
	CardToken *struct {
		Header    ResponseHeader `json:"header,omitempty"`
		CardToken any            `json:"cardToken,omitempty"`
		HashData  any            `json:"hashData,omitempty"`
	}
	Provision *struct {
		Header       ResponseHeader `json:"responseHeader,omitempty"`
		OrderId      any            `json:"orderId,omitempty"`
		OrderDate    any            `json:"reconciliationDate,omitempty"`
		ApprovalCode any            `json:"approvalCodeo,omitempty"`
		AcquirerBank any            `json:"acquirerBankCode,omitempty"`
		IssuerBank   any            `json:"issuerBankCode,omitempty"`
	}
	ThreeDSession *struct {
		Header        ResponseHeader `json:"responseHeader,omitempty"`
		ThreeDSession any            `json:"threeDSessionId,omitempty"`
	}
	ThreeDResult *struct {
		CurrentStep    any `json:"currentStep,omitempty"`
		MdErrorMessage any `json:"mdErrorMessage,omitempty"`
		MdStatus       any `json:"mdStatus,omitempty"`
		Operation      struct {
			Result      any `json:"threeDResult,omitempty"`
			Description any `json:"threeDResultDescription,omitempty"`
		} `json:"threeDOperationResult,omitempty"`
	}
	PaymentMethods *struct {
		Header   ResponseHeader `json:"responseHeader,omitempty"`
		EulaID   any            `json:"eulaID,omitempty"`
		CardList []*struct {
			CardBrand         any  `json:"cardBrand,omitempty"`
			CardId            any  `json:"cardId,omitempty"`
			CardType          any  `json:"cardType,omitempty"`
			MaskedCardNo      any  `json:"maskedCardNo,omitempty"`
			Alias             any  `json:"alias,omitempty"`
			ActivationDate    any  `json:"activationDate,omitempty"`
			IsDefault         bool `json:"isDefault,omitempty"`
			IsExpired         bool `json:"isExpired,omitempty"`
			ShowEulaId        bool `json:"showEulaId,omitempty"`
			IsThreeDValidated bool `json:"isThreeDValidated,omitempty"`
			IsOTPValidated    bool `json:"isOTPValidated,omitempty"`
		} `json:"cardList,omitempty"`
		MobilePayment *struct {
			EulaId         any  `json:"eulaId,omitempty"`
			EulaUrl        any  `json:"eulaUrl,omitempty"`
			SignedEulaId   any  `json:"signedEulaId,omitempty"`
			StatementDate  any  `json:"statementDate,omitempty"`
			Limit          any  `json:"limit,omitempty"`
			MaxLimit       any  `json:"maxLimit,omitempty"`
			RemainingLimit any  `json:"remainingLimit,omitempty"`
			IsDcbOpen      bool `json:"isDcbOpen,omitempty"`
			IsEulaExpired  bool `json:"isEulaExpired,omitempty"`
		} `json:"mobilePayment,omitempty"`
	}
	MobilePayment *struct {
		Header ResponseHeader `json:"responseHeader,omitempty"`
	}
	OTP *struct {
		Header     ResponseHeader `json:"responseHeader,omitempty"`
		Token      any            `json:"token,omitempty"`
		ExpireDate any            `json:"expireDate,omitempty"`
		RetryCount any            `json:"remainingRetryCount,omitempty"`
	}
}

type RequestHeader struct {
	ApplicationName     string `json:"applicationName,omitempty"`
	ApplicationPwd      string `json:"applicationPwd,omitempty"`
	ClientIPAddress     string `json:"clientIPAddress,omitempty"`
	TransactionDateTime string `json:"transactionDateTime,omitempty"`
	TransactionId       string `json:"transactionId,omitempty"`
}

type ResponseHeader *struct {
	ResponseCode        string `json:"responseCode,omitempty"`
	ResponseDescription string `json:"responseDescription,omitempty"`
	ResponseDateTime    string `json:"responseDateTime,omitempty"`
	TransactionId       string `json:"transactionId,omitempty"`
}

func SHA256(data string) (hash string) {
	h := sha256.New()
	h.Write([]byte(data))
	hash = base64.StdEncoding.EncodeToString(h.Sum(nil))
	return hash
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

func Api(msisdn string) (*API, *Request) {
	api := new(API)
	api.MSisdn = msisdn
	req := new(Request)
	return api, req
}

func (api *API) SetMode(mode string) {
	api.Mode = mode
}

func (api *API) SetIPAddress(ip string) {
	api.ClientIP = ip
}

func (api *API) SetAmount(total string, currency string) {
	api.Amount = strings.ReplaceAll(total, ".", "")
	api.Currency = currency
}

func (req *Request) SetCardNumber(number string) {
	req.CardToken.CardNumber = number
}

func (req *Request) SetCardExpiry(month, year string) {
	req.CardToken.CardMonth = month
	req.CardToken.CardYear = year
}

func (req *Request) SetCardCode(code string) {
	req.CardToken.CardCode = code
}

func (api *API) HashResponse(header ResponseHeader, cardToken string) string {
	hashdata := SHA256(strings.ToUpper(Application + header.TransactionId + header.ResponseDateTime + header.ResponseCode + cardToken + StoreKey + SHA256(strings.ToUpper(Password+Application))))
	return hashdata
}

func (api *API) Auth(req *Request) (res Response, err error) {
	apiurl := Endpoint[api.Mode] + "/provision/"
	req.Provision.Header.ClientIPAddress = api.ClientIP
	req.Provision.Header.ApplicationName = Application
	req.Provision.Header.ApplicationPwd = Password
	req.Provision.Header.TransactionDateTime = strings.ReplaceAll(time.Now().Format("20060102150405.000"), ".", "")
	req.Provision.Header.TransactionId = Random(20)
	req.Provision.MSisdn = api.MSisdn
	req.Provision.MerchantCode = Merchant
	req.Provision.RefNo = Prefix + fmt.Sprintf("%v", req.Provision.Header.TransactionDateTime)
	req.Provision.Amount = api.Amount
	req.Provision.Currency = api.Currency
	req.Provision.PaymentType = "SALE"
	postdata, err := json.Marshal(req.Provision)
	if err != nil {
		return res, err
	}
	cli := new(http.Client)
	request, err := http.NewRequest("POST", apiurl, bytes.NewReader(postdata))
	if err != nil {
		return res, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := cli.Do(request)
	if err != nil {
		return res, err
	}
	defer response.Body.Close()
	decoder := json.NewDecoder(response.Body)
	decoder.UseNumber()
	decoder.Decode(&res.Provision)
	return res, err
}

func (api *API) PreAuth(req *Request) (res Response, err error) {
	apiurl := Endpoint[api.Mode] + "/provision/"
	req.Provision.Header.ClientIPAddress = api.ClientIP
	req.Provision.Header.ApplicationName = Application
	req.Provision.Header.ApplicationPwd = Password
	req.Provision.Header.TransactionDateTime = strings.ReplaceAll(time.Now().Format("20060102150405.000"), ".", "")
	req.Provision.Header.TransactionId = Random(20)
	req.Provision.MSisdn = api.MSisdn
	req.Provision.MerchantCode = Merchant
	req.Provision.RefNo = Prefix + fmt.Sprintf("%v", req.Provision.Header.TransactionDateTime)
	req.Provision.Amount = api.Amount
	req.Provision.Currency = api.Currency
	req.Provision.PaymentType = "PREAUTH"
	postdata, err := json.Marshal(req.Provision)
	if err != nil {
		return res, err
	}
	cli := new(http.Client)
	request, err := http.NewRequest("POST", apiurl, bytes.NewReader(postdata))
	if err != nil {
		return res, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := cli.Do(request)
	if err != nil {
		return res, err
	}
	defer response.Body.Close()
	decoder := json.NewDecoder(response.Body)
	decoder.UseNumber()
	decoder.Decode(&res.Provision)
	return res, err
}

func (api *API) PostAuth(req *Request) (res Response, err error) {
	apiurl := Endpoint[api.Mode] + "/provision/"
	req.Provision.Header.ClientIPAddress = api.ClientIP
	req.Provision.Header.ApplicationName = Application
	req.Provision.Header.ApplicationPwd = Password
	req.Provision.Header.TransactionDateTime = strings.ReplaceAll(time.Now().Format("20060102150405.000"), ".", "")
	req.Provision.Header.TransactionId = Random(20)
	req.Provision.MSisdn = api.MSisdn
	req.Provision.MerchantCode = Merchant
	req.Provision.RefNo = Prefix + fmt.Sprintf("%v", req.Provision.Header.TransactionDateTime)
	req.Provision.Amount = api.Amount
	req.Provision.Currency = api.Currency
	req.Provision.PaymentType = "POSTAUTH"
	postdata, err := json.Marshal(req.Provision)
	if err != nil {
		return res, err
	}
	cli := new(http.Client)
	request, err := http.NewRequest("POST", apiurl, bytes.NewReader(postdata))
	if err != nil {
		return res, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := cli.Do(request)
	if err != nil {
		return res, err
	}
	defer response.Body.Close()
	decoder := json.NewDecoder(response.Body)
	decoder.UseNumber()
	decoder.Decode(&res.Provision)
	return res, err
}

func (api *API) ThreeDSession(req *Request) (res Response, err error) {
	apiurl := Endpoint[api.Mode] + "/getThreeDSession/"
	req.ThreeDSession.Header.ClientIPAddress = api.ClientIP
	req.ThreeDSession.Header.ApplicationName = Application
	req.ThreeDSession.Header.ApplicationPwd = Password
	req.ThreeDSession.Header.TransactionDateTime = strings.ReplaceAll(time.Now().Format("20060102150405.000"), ".", "")
	req.ThreeDSession.Header.TransactionId = Random(20)
	req.ThreeDSession.MSisdn = api.MSisdn
	req.ThreeDSession.MerchantCode = Merchant
	req.ThreeDSession.RefNo = Prefix + fmt.Sprintf("%v", req.ThreeDSession.Header.TransactionDateTime)
	req.ThreeDSession.Amount = api.Amount
	req.ThreeDSession.Currency = api.Currency
	postdata, err := json.Marshal(req.ThreeDSession)
	if err != nil {
		return res, err
	}
	cli := new(http.Client)
	request, err := http.NewRequest("POST", apiurl, bytes.NewReader(postdata))
	if err != nil {
		return res, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := cli.Do(request)
	if err != nil {
		return res, err
	}
	defer response.Body.Close()
	decoder := json.NewDecoder(response.Body)
	decoder.UseNumber()
	decoder.Decode(&res.ThreeDSession)
	return res, err
}

func (api *API) ThreeDResult(ctx context.Context, req *Request) (res Response, err error) {
	apiurl := Endpoint[api.Mode] + "/getThreeDSessionResult/"
	req.ThreeDResult.Header.ClientIPAddress = api.ClientIP
	req.ThreeDResult.Header.ApplicationName = Application
	req.ThreeDResult.Header.ApplicationPwd = Password
	req.ThreeDResult.Header.TransactionDateTime = strings.ReplaceAll(time.Now().Format("20060102150405.000"), ".", "")
	req.ThreeDResult.Header.TransactionId = Random(20)
	req.ThreeDResult.MSisdn = api.MSisdn
	req.ThreeDResult.MerchantCode = Merchant
	req.ThreeDResult.RefNo = Prefix + fmt.Sprintf("%v", req.ThreeDResult.Header.TransactionDateTime)
	postdata, err := json.Marshal(req.ThreeDResult)
	if err != nil {
		return res, err
	}
	cli := new(http.Client)
	request, err := http.NewRequest("POST", apiurl, bytes.NewReader(postdata))
	if err != nil {
		return res, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := cli.Do(request)
	if err != nil {
		return res, err
	}
	defer response.Body.Close()
	decoder := json.NewDecoder(response.Body)
	decoder.UseNumber()
	decoder.Decode(&res.ThreeDResult)
	return res, err
}

func (api *API) CardToken(ctx context.Context, req *Request) (res Response, err error) {
	req.CardToken.Header.ApplicationName = Application
	req.CardToken.Header.TransactionDateTime = strings.ReplaceAll(time.Now().Format("20060102150405.000"), ".", "")
	req.CardToken.Header.TransactionId = Random(20)
	req.CardToken.HashData = SHA256(strings.ToUpper(Application + req.CardToken.Header.TransactionId + req.CardToken.Header.TransactionDateTime + StoreKey + SHA256(strings.ToUpper(Password+Application))))
	postdata, err := json.Marshal(req.CardToken)
	if err != nil {
		return res, err
	}
	cli := new(http.Client)
	request, err := http.NewRequestWithContext(ctx, "POST", Endpoint[api.Mode+"_TOKEN"], bytes.NewReader(postdata))
	if err != nil {
		return res, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := cli.Do(request)
	if err != nil {
		return res, err
	}
	defer response.Body.Close()
	decoder := json.NewDecoder(response.Body)
	decoder.UseNumber()
	decoder.Decode(&res.CardToken)
	return res, err
}

func (api *API) GetPaymentMethods(req *Request) (res Response, err error) {
	apiurl := Endpoint[api.Mode] + "/getPaymentMethods/"
	req.PaymentMethods.MSisdn = api.MSisdn
	req.PaymentMethods.Header.ClientIPAddress = api.ClientIP
	req.PaymentMethods.Header.ApplicationName = Application
	req.PaymentMethods.Header.ApplicationPwd = Password
	req.PaymentMethods.Header.TransactionDateTime = strings.ReplaceAll(time.Now().Format("20060102150405.000"), ".", "")
	req.PaymentMethods.Header.TransactionId = Random(20)
	postdata, err := json.Marshal(req.PaymentMethods)
	if err != nil {
		return res, err
	}
	cli := new(http.Client)
	request, err := http.NewRequest("POST", apiurl, bytes.NewReader(postdata))
	if err != nil {
		return res, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := cli.Do(request)
	if err != nil {
		return res, err
	}
	defer response.Body.Close()
	decoder := json.NewDecoder(response.Body)
	decoder.UseNumber()
	decoder.Decode(&res.PaymentMethods)
	return res, err
}

func (api *API) OpenMobilePayment(ctx context.Context, req *Request) (res Response, err error) {
	apiurl := Endpoint[api.Mode] + "/openMobilePayment/"
	req.MobilePayment.Header.ClientIPAddress = api.ClientIP
	req.MobilePayment.Header.ApplicationName = Application
	req.MobilePayment.Header.ApplicationPwd = Password
	req.MobilePayment.Header.TransactionDateTime = strings.ReplaceAll(time.Now().Format("20060102150405.000"), ".", "")
	req.MobilePayment.Header.TransactionId = Random(20)
	req.MobilePayment.MSisdn = api.MSisdn
	postdata, err := json.Marshal(req.MobilePayment)
	if err != nil {
		return res, err
	}
	cli := new(http.Client)
	request, err := http.NewRequest("POST", apiurl, bytes.NewReader(postdata))
	if err != nil {
		return res, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := cli.Do(request)
	if err != nil {
		return res, err
	}
	defer response.Body.Close()
	decoder := json.NewDecoder(response.Body)
	decoder.UseNumber()
	decoder.Decode(&res.MobilePayment)
	return res, err
}

func (api *API) SendOTP(req *Request) (res Response, err error) {
	apiurl := Endpoint[api.Mode] + "/sendOTP/"
	req.OTP.Header.ClientIPAddress = api.ClientIP
	req.OTP.Header.ApplicationName = Application
	req.OTP.Header.ApplicationPwd = Password
	req.OTP.Header.TransactionDateTime = strings.ReplaceAll(time.Now().Format("20060102150405.000"), ".", "")
	req.OTP.Header.TransactionId = Random(20)
	req.OTP.MSisdn = api.MSisdn
	req.OTP.RefNo = Random(20)
	req.OTP.Amount = api.Amount
	req.OTP.Currency = api.Currency
	postdata, err := json.Marshal(req.OTP)
	if err != nil {
		return res, err
	}
	cli := new(http.Client)
	request, err := http.NewRequest("POST", apiurl, bytes.NewReader(postdata))
	if err != nil {
		return res, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := cli.Do(request)
	if err != nil {
		return res, err
	}
	defer response.Body.Close()
	decoder := json.NewDecoder(response.Body)
	decoder.UseNumber()
	decoder.Decode(&res.OTP)
	return res, err
}

func (api *API) ValidateOTP(ctx context.Context, req *Request) (res Response, err error) {
	apiurl := Endpoint[api.Mode] + "/validateOTP/"
	req.OTP.Header.ClientIPAddress = api.ClientIP
	req.OTP.Header.ApplicationName = Application
	req.OTP.Header.ApplicationPwd = Password
	req.OTP.Header.TransactionDateTime = strings.ReplaceAll(time.Now().Format("20060102150405.000"), ".", "")
	req.OTP.Header.TransactionId = Random(20)
	req.OTP.MSisdn = api.MSisdn
	req.OTP.RefNo = Random(20)
	req.OTP.Amount = api.Amount
	req.OTP.Currency = api.Currency
	postdata, err := json.Marshal(req.OTP)
	if err != nil {
		return res, err
	}
	cli := new(http.Client)
	request, err := http.NewRequest("POST", apiurl, bytes.NewReader(postdata))
	if err != nil {
		return res, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := cli.Do(request)
	if err != nil {
		return res, err
	}
	defer response.Body.Close()
	decoder := json.NewDecoder(response.Body)
	decoder.UseNumber()
	decoder.Decode(&res.OTP)
	return res, err
}
