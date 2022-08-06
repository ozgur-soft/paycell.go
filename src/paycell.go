package paycell

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

var (
	Endpoints = map[string]string{
		"PROD":       "https://tpay.turkcell.com.tr/tpay/provision/services/restful/getCardToken",
		"TEST":       "https://tpay-test.turkcell.com.tr/tpay/provision/services/restful/getCardToken",
		"PROD_TOKEN": "https://epayment.turkcell.com.tr/paymentmanagement/rest/getCardTokenSecure",
		"TEST_TOKEN": "https://omccstb.turkcell.com.tr/paymentmanagement/rest/getCardTokenSecure",
		"PROD_FORM":  "https://epayment.turkcell.com.tr/paymentmanagement/rest/threeDSecure",
		"TEST_FORM":  "https://omccstb.turkcell.com.tr/paymentmanagement/rest/threeDSecure",
	}
)

type any = interface{}

type API struct {
	Mode     string
	Merchant string
	Password string
	Name     string
	Key      string
	EulaId   string
	Prefix   string
	ISDN     string
	IPv4     string
	Amount   string
	Currency string
}

type (
	Request struct {
		CardToken struct {
			Header     RequestHeader `json:"header,omitempty"`
			CardNumber any           `json:"creditCardNo,omitempty"`
			CardMonth  any           `json:"expireDateMonth,omitempty"`
			CardYear   any           `json:"expireDateYear,omitempty"`
			CardCode   any           `json:"cvcNo,omitempty"`
			Hash       any           `json:"hashData,omitempty"`
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
		Cancel struct {
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
)

type (
	Response struct {
		CardToken *struct {
			Header ResponseHeader `json:"header,omitempty"`
			Token  string         `json:"cardToken,omitempty"`
			Hash   string         `json:"hashData,omitempty"`
		}
		Provision *struct {
			Header       ResponseHeader `json:"responseHeader,omitempty"`
			OrderId      any            `json:"orderId,omitempty"`
			RefNo        any            `json:"referenceNumber,omitempty"`
			OrderDate    any            `json:"reconciliationDate,omitempty"`
			ApprovalCode any            `json:"approvalCode,omitempty"`
			AcquirerBank any            `json:"acquirerBankCode,omitempty"`
			IssuerBank   any            `json:"issuerBankCode,omitempty"`
		}
		Refund *struct {
			Header       ResponseHeader `json:"responseHeader,omitempty"`
			OrderId      any            `json:"orderId,omitempty"`
			OrderDate    any            `json:"reconciliationDate,omitempty"`
			ApprovalCode any            `json:"approvalCode,omitempty"`
			StatusCode   any            `json:"retryStatusCode,omitempty"`
			Description  any            `json:"retryStatusDescription,omitempty"`
		}
		Cancel *struct {
			Header       ResponseHeader `json:"responseHeader,omitempty"`
			OrderId      any            `json:"orderId,omitempty"`
			OrderDate    any            `json:"reconciliationDate,omitempty"`
			ApprovalCode any            `json:"approvalCode,omitempty"`
			StatusCode   any            `json:"retryStatusCode,omitempty"`
			Description  any            `json:"retryStatusDescription,omitempty"`
		}
		ThreeDSession *struct {
			Header        ResponseHeader `json:"responseHeader,omitempty"`
			ThreeDSession any            `json:"threeDSessionId,omitempty"`
		}
		ThreeDResult *struct {
			Header         ResponseHeader `json:"responseHeader,omitempty"`
			CurrentStep    any            `json:"currentStep,omitempty"`
			MdErrorMessage any            `json:"mdErrorMessage,omitempty"`
			MdStatus       any            `json:"mdStatus,omitempty"`
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
)

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

func Api(merchant, password, name string) (*API, *Request) {
	api := new(API)
	api.Merchant = merchant
	api.Password = password
	api.Name = name
	req := new(Request)
	return api, req
}

func (api *API) SetStoreKey(key string) {
	api.Key = key
}

func (api *API) SetPrefix(prefix string) {
	api.Prefix = prefix
}

func (api *API) SetMode(mode string) {
	api.Mode = mode
}

func (api *API) SetIPAddress(ip string) {
	api.IPv4 = ip
}

func (api *API) SetPhoneNumber(isdn string) {
	api.ISDN = isdn
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

func (api *API) Hash(res Response) string {
	hashdata := SHA256(strings.ToUpper(api.Name + res.CardToken.Header.TransactionId + res.CardToken.Header.ResponseDateTime + res.CardToken.Header.ResponseCode + res.CardToken.Token + api.Key + SHA256(strings.ToUpper(api.Password+api.Name))))
	return hashdata
}

func (api *API) PreAuth(ctx context.Context, req *Request) (res Response, err error) {
	token, err := api.CardToken(context.Background(), req)
	if err != nil {
		return res, err
	}
	req.Provision.CardToken = token.CardToken.Token
	req.Provision.Header.ClientIPAddress = api.IPv4
	req.Provision.Header.ApplicationName = api.Name
	req.Provision.Header.ApplicationPwd = api.Password
	req.Provision.Header.TransactionDateTime = strings.ReplaceAll(time.Now().Format("20060102150405.000"), ".", "")
	req.Provision.Header.TransactionId = Random(20)
	req.Provision.MSisdn = api.ISDN
	req.Provision.MerchantCode = api.Merchant
	req.Provision.RefNo = api.Prefix + fmt.Sprintf("%v", req.Provision.Header.TransactionDateTime)
	req.Provision.Amount = api.Amount
	req.Provision.Currency = api.Currency
	req.Provision.PaymentType = "PREAUTH"
	postdata, err := json.Marshal(req.Provision)
	if err != nil {
		return res, err
	}
	cli := new(http.Client)
	request, err := http.NewRequestWithContext(ctx, "POST", Endpoints[api.Mode]+"/provision/", bytes.NewReader(postdata))
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
	switch res.Provision.Header.ResponseCode {
	case "0":
		res.Provision.RefNo = req.Provision.RefNo
		return res, nil
	default:
		return res, errors.New(res.Provision.Header.ResponseDescription)
	}
}

func (api *API) Auth(ctx context.Context, req *Request) (res Response, err error) {
	token, err := api.CardToken(context.Background(), req)
	if err != nil {
		return res, err
	}
	req.Provision.CardToken = token.CardToken.Token
	req.Provision.Header.ClientIPAddress = api.IPv4
	req.Provision.Header.ApplicationName = api.Name
	req.Provision.Header.ApplicationPwd = api.Password
	req.Provision.Header.TransactionDateTime = strings.ReplaceAll(time.Now().Format("20060102150405.000"), ".", "")
	req.Provision.Header.TransactionId = Random(20)
	req.Provision.MSisdn = api.ISDN
	req.Provision.MerchantCode = api.Merchant
	req.Provision.RefNo = api.Prefix + fmt.Sprintf("%v", req.Provision.Header.TransactionDateTime)
	req.Provision.Amount = api.Amount
	req.Provision.Currency = api.Currency
	req.Provision.PaymentType = "SALE"
	postdata, err := json.Marshal(req.Provision)
	if err != nil {
		return res, err
	}
	cli := new(http.Client)
	request, err := http.NewRequestWithContext(ctx, "POST", Endpoints[api.Mode]+"/provision/", bytes.NewReader(postdata))
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
	switch res.Provision.Header.ResponseCode {
	case "0":
		res.Provision.RefNo = req.Provision.RefNo
		return res, nil
	default:
		return res, errors.New(res.Provision.Header.ResponseDescription)
	}
}

func (api *API) PostAuth(ctx context.Context, req *Request) (res Response, err error) {
	req.Provision.Header.ClientIPAddress = api.IPv4
	req.Provision.Header.ApplicationName = api.Name
	req.Provision.Header.ApplicationPwd = api.Password
	req.Provision.Header.TransactionDateTime = strings.ReplaceAll(time.Now().Format("20060102150405.000"), ".", "")
	req.Provision.Header.TransactionId = Random(20)
	req.Provision.MSisdn = api.ISDN
	req.Provision.MerchantCode = api.Merchant
	req.Provision.RefNo = api.Prefix + fmt.Sprintf("%v", req.Provision.Header.TransactionDateTime)
	req.Provision.Amount = api.Amount
	req.Provision.Currency = api.Currency
	req.Provision.PaymentType = "POSTAUTH"
	postdata, err := json.Marshal(req.Provision)
	if err != nil {
		return res, err
	}
	cli := new(http.Client)
	request, err := http.NewRequestWithContext(ctx, "POST", Endpoints[api.Mode]+"/provision/", bytes.NewReader(postdata))
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
	switch res.Provision.Header.ResponseCode {
	case "0":
		return res, nil
	default:
		return res, errors.New(res.Provision.Header.ResponseDescription)
	}
}

func (api *API) Refund(ctx context.Context, req *Request) (res Response, err error) {
	req.Refund.Header.ClientIPAddress = api.IPv4
	req.Refund.Header.ApplicationName = api.Name
	req.Refund.Header.ApplicationPwd = api.Password
	req.Refund.Header.TransactionDateTime = strings.ReplaceAll(time.Now().Format("20060102150405.000"), ".", "")
	req.Refund.Header.TransactionId = Random(20)
	req.Refund.MSisdn = api.ISDN
	req.Refund.MerchantCode = api.Merchant
	req.Refund.RefNo = api.Prefix + fmt.Sprintf("%v", req.Refund.Header.TransactionDateTime)
	req.Refund.Amount = api.Amount
	req.Refund.Currency = api.Currency
	postdata, err := json.Marshal(req.Refund)
	if err != nil {
		return res, err
	}
	cli := new(http.Client)
	request, err := http.NewRequestWithContext(ctx, "POST", Endpoints[api.Mode]+"/refund/", bytes.NewReader(postdata))
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
	decoder.Decode(&res.Refund)
	switch res.Refund.Header.ResponseCode {
	case "0":
		return res, nil
	default:
		return res, errors.New(res.Refund.Header.ResponseDescription)
	}
}

func (api *API) Cancel(ctx context.Context, req *Request) (res Response, err error) {
	req.Cancel.Header.ClientIPAddress = api.IPv4
	req.Cancel.Header.ApplicationName = api.Name
	req.Cancel.Header.ApplicationPwd = api.Password
	req.Cancel.Header.TransactionDateTime = strings.ReplaceAll(time.Now().Format("20060102150405.000"), ".", "")
	req.Cancel.Header.TransactionId = Random(20)
	req.Cancel.MSisdn = api.ISDN
	req.Cancel.MerchantCode = api.Merchant
	req.Cancel.RefNo = api.Prefix + fmt.Sprintf("%v", req.Cancel.Header.TransactionDateTime)
	postdata, err := json.Marshal(req.Cancel)
	if err != nil {
		return res, err
	}
	cli := new(http.Client)
	request, err := http.NewRequestWithContext(ctx, "POST", Endpoints[api.Mode]+"/reverse/", bytes.NewReader(postdata))
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
	decoder.Decode(&res.Cancel)
	switch res.Cancel.Header.ResponseCode {
	case "0":
		return res, nil
	default:
		return res, errors.New(res.Cancel.Header.ResponseDescription)
	}
}

func (api *API) ThreeDSession(ctx context.Context, req *Request) (res Response, err error) {
	req.ThreeDSession.Header.ClientIPAddress = api.IPv4
	req.ThreeDSession.Header.ApplicationName = api.Name
	req.ThreeDSession.Header.ApplicationPwd = api.Password
	req.ThreeDSession.Header.TransactionDateTime = strings.ReplaceAll(time.Now().Format("20060102150405.000"), ".", "")
	req.ThreeDSession.Header.TransactionId = Random(20)
	req.ThreeDSession.MSisdn = api.ISDN
	req.ThreeDSession.MerchantCode = api.Merchant
	req.ThreeDSession.RefNo = api.Prefix + fmt.Sprintf("%v", req.ThreeDSession.Header.TransactionDateTime)
	req.ThreeDSession.Amount = api.Amount
	req.ThreeDSession.Currency = api.Currency
	postdata, err := json.Marshal(req.ThreeDSession)
	if err != nil {
		return res, err
	}
	cli := new(http.Client)
	request, err := http.NewRequestWithContext(ctx, "POST", Endpoints[api.Mode]+"/getThreeDSession/", bytes.NewReader(postdata))
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
	switch res.ThreeDSession.Header.ResponseCode {
	case "0":
		return res, nil
	default:
		return res, errors.New(res.ThreeDSession.Header.ResponseDescription)
	}
}

func (api *API) ThreeDResult(ctx context.Context, req *Request) (res Response, err error) {
	req.ThreeDResult.Header.ClientIPAddress = api.IPv4
	req.ThreeDResult.Header.ApplicationName = api.Name
	req.ThreeDResult.Header.ApplicationPwd = api.Password
	req.ThreeDResult.Header.TransactionDateTime = strings.ReplaceAll(time.Now().Format("20060102150405.000"), ".", "")
	req.ThreeDResult.Header.TransactionId = Random(20)
	req.ThreeDResult.MSisdn = api.ISDN
	req.ThreeDResult.MerchantCode = api.Merchant
	req.ThreeDResult.RefNo = api.Prefix + fmt.Sprintf("%v", req.ThreeDResult.Header.TransactionDateTime)
	postdata, err := json.Marshal(req.ThreeDResult)
	if err != nil {
		return res, err
	}
	cli := new(http.Client)
	request, err := http.NewRequestWithContext(ctx, "POST", Endpoints[api.Mode]+"/getThreeDSessionResult/", bytes.NewReader(postdata))
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
	switch res.ThreeDResult.Header.ResponseCode {
	case "0":
		return res, nil
	default:
		return res, errors.New(res.ThreeDResult.Header.ResponseDescription)
	}
}

func (api *API) CardToken(ctx context.Context, req *Request) (res Response, err error) {
	req.CardToken.Header.ApplicationName = api.Name
	req.CardToken.Header.TransactionDateTime = strings.ReplaceAll(time.Now().Format("20060102150405.000"), ".", "")
	req.CardToken.Header.TransactionId = Random(20)
	req.CardToken.Hash = SHA256(strings.ToUpper(api.Name + req.CardToken.Header.TransactionId + req.CardToken.Header.TransactionDateTime + api.Key + SHA256(strings.ToUpper(api.Password+api.Name))))
	postdata, err := json.Marshal(req.CardToken)
	if err != nil {
		return res, err
	}
	cli := new(http.Client)
	request, err := http.NewRequestWithContext(ctx, "POST", Endpoints[api.Mode+"_TOKEN"], bytes.NewReader(postdata))
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
	switch res.CardToken.Header.ResponseCode {
	case "0":
		if res.CardToken.Hash != api.Hash(res) {
			return res, errors.New("mismatched hash")
		}
		return res, nil
	default:
		return res, errors.New(res.CardToken.Header.ResponseDescription)
	}
}

func (api *API) GetPaymentMethods(ctx context.Context, req *Request) (res Response, err error) {
	req.PaymentMethods.MSisdn = api.ISDN
	req.PaymentMethods.Header.ClientIPAddress = api.IPv4
	req.PaymentMethods.Header.ApplicationName = api.Name
	req.PaymentMethods.Header.ApplicationPwd = api.Password
	req.PaymentMethods.Header.TransactionDateTime = strings.ReplaceAll(time.Now().Format("20060102150405.000"), ".", "")
	req.PaymentMethods.Header.TransactionId = Random(20)
	postdata, err := json.Marshal(req.PaymentMethods)
	if err != nil {
		return res, err
	}
	cli := new(http.Client)
	request, err := http.NewRequestWithContext(ctx, "POST", Endpoints[api.Mode]+"/getPaymentMethods/", bytes.NewReader(postdata))
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
	switch res.PaymentMethods.Header.ResponseCode {
	case "0":
		return res, nil
	default:
		return res, errors.New(res.PaymentMethods.Header.ResponseDescription)
	}
}

func (api *API) OpenMobilePayment(ctx context.Context, req *Request) (res Response, err error) {
	req.MobilePayment.Header.ClientIPAddress = api.IPv4
	req.MobilePayment.Header.ApplicationName = api.Name
	req.MobilePayment.Header.ApplicationPwd = api.Password
	req.MobilePayment.Header.TransactionDateTime = strings.ReplaceAll(time.Now().Format("20060102150405.000"), ".", "")
	req.MobilePayment.Header.TransactionId = Random(20)
	req.MobilePayment.MSisdn = api.ISDN
	postdata, err := json.Marshal(req.MobilePayment)
	if err != nil {
		return res, err
	}
	cli := new(http.Client)
	request, err := http.NewRequestWithContext(ctx, "POST", Endpoints[api.Mode]+"/openMobilePayment/", bytes.NewReader(postdata))
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
	switch res.MobilePayment.Header.ResponseCode {
	case "0":
		return res, nil
	default:
		return res, errors.New(res.MobilePayment.Header.ResponseDescription)
	}
}

func (api *API) SendOTP(ctx context.Context, req *Request) (res Response, err error) {
	req.OTP.Header.ClientIPAddress = api.IPv4
	req.OTP.Header.ApplicationName = api.Name
	req.OTP.Header.ApplicationPwd = api.Password
	req.OTP.Header.TransactionDateTime = strings.ReplaceAll(time.Now().Format("20060102150405.000"), ".", "")
	req.OTP.Header.TransactionId = Random(20)
	req.OTP.MSisdn = api.ISDN
	req.OTP.RefNo = Random(20)
	req.OTP.Amount = api.Amount
	req.OTP.Currency = api.Currency
	postdata, err := json.Marshal(req.OTP)
	if err != nil {
		return res, err
	}
	cli := new(http.Client)
	request, err := http.NewRequestWithContext(ctx, "POST", Endpoints[api.Mode]+"/sendOTP/", bytes.NewReader(postdata))
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
	switch res.OTP.Header.ResponseCode {
	case "0":
		return res, nil
	default:
		return res, errors.New(res.OTP.Header.ResponseDescription)
	}
}

func (api *API) ValidateOTP(ctx context.Context, req *Request) (res Response, err error) {
	req.OTP.Header.ClientIPAddress = api.IPv4
	req.OTP.Header.ApplicationName = api.Name
	req.OTP.Header.ApplicationPwd = api.Password
	req.OTP.Header.TransactionDateTime = strings.ReplaceAll(time.Now().Format("20060102150405.000"), ".", "")
	req.OTP.Header.TransactionId = Random(20)
	req.OTP.MSisdn = api.ISDN
	req.OTP.RefNo = Random(20)
	req.OTP.Amount = api.Amount
	req.OTP.Currency = api.Currency
	postdata, err := json.Marshal(req.OTP)
	if err != nil {
		return res, err
	}
	cli := new(http.Client)
	request, err := http.NewRequestWithContext(ctx, "POST", Endpoints[api.Mode]+"/validateOTP/", bytes.NewReader(postdata))
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
	switch res.OTP.Header.ResponseCode {
	case "0":
		return res, nil
	default:
		return res, errors.New(res.OTP.Header.ResponseDescription)
	}
}
