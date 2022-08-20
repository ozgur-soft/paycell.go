package paycell

import (
	"context"
	"encoding/json"
	"testing"
)

const (
	envmode  = "TEST"                // Çalışma ortamı (Production : "PROD" - Test : "TEST")
	merchant = "9998"                // İşyeri numarası
	appname  = "PAYCELLTEST"         // Uygulama adı
	apppass  = "PaycellTestPassword" // Uygulama şifresi
	storekey = "PAYCELL12345"        // İşyeri anahtarı
	prefix   = "666"                 // Referans no ilk 3 hanesi
)

func Auth() (res Response, err error) {
	api, req := Api(merchant, apppass, appname)
	api.SetStoreKey(storekey)
	api.SetPrefix(prefix)
	api.SetMode(envmode)
	api.SetIPAddress("127.0.0.1")         // IP adresi (zorunlu)
	api.SetPhoneNumber("905305289290")    // Müşteri numarası (zorunlu)
	api.SetAmount("1.00", "TRY")          // Satış tutarı (zorunlu)
	req.SetCardNumber("4355084355084358") // Kart numarası (zorunlu)
	req.SetCardExpiry("12", "26")         // Son kullanma tarihi - AA,YY (zorunlu)
	req.SetCardCode("000")                // Kart arkasındaki 3 haneli numara (zorunlu)
	req.Provision.Installment = "0"       // Taksit sayısı (varsa)
	return api.Auth(context.Background(), req)
}

func Refund(ref string) (res Response, err error) {
	api, req := Api(merchant, apppass, appname)
	api.SetStoreKey(storekey)
	api.SetPrefix(prefix)
	api.SetMode(envmode)
	api.SetPhoneNumber("905305289290") // Müşteri numarası (zorunlu)
	api.SetIPAddress("127.0.0.1")      // IP adresi (zorunlu)
	api.SetAmount("1.00", "TRY")       // İade tutarı (zorunlu)
	req.Refund.OriginalRefNo = ref
	return api.Refund(context.Background(), req)
}

func Cancel(ref string) (res Response, err error) {
	api, req := Api(merchant, apppass, appname)
	api.SetStoreKey(storekey)
	api.SetPrefix(prefix)
	api.SetMode(envmode)
	api.SetPhoneNumber("905305289290") // Müşteri numarası (zorunlu)
	api.SetIPAddress("127.0.0.1")      // IP adresi (zorunlu)
	req.Cancel.OriginalRefNo = ref
	return api.Cancel(context.Background(), req)
}

func TestAuth(t *testing.T) {
	if auth, err := Auth(); err == nil {
		if pretty, err := json.MarshalIndent(auth.Provision, " ", " "); err == nil {
			t.Log(string(pretty))
		} else {
			t.Error(err)
		}
	} else {
		t.Error(err)
	}
}

func TestRefund(t *testing.T) {
	if auth, err := Auth(); err == nil {
		if res, err := Refund(auth.Provision.RefNo.(string)); err == nil {
			if pretty, err := json.MarshalIndent(res.Refund, " ", " "); err == nil {
				t.Log(string(pretty))
			} else {
				t.Error(err)
			}
		} else {
			t.Error(err)
		}
	} else {
		t.Error(err)
	}
}

func TestCancel(t *testing.T) {
	if auth, err := Auth(); err == nil {
		if res, err := Cancel(auth.Provision.RefNo.(string)); err == nil {
			if pretty, err := json.MarshalIndent(res.Cancel, " ", " "); err == nil {
				t.Log(string(pretty))
			} else {
				t.Error(err)
			}
		} else {
			t.Error(err)
		}
	} else {
		t.Error(err)
	}
}
