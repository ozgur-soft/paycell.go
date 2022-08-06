# Paycell.go
Turkcell (Paycell) API with golang

# Installation
```bash
go get github.com/ozgur-soft/paycell.go
```

# Satış işlemi
```go
package main

import (
	"context"
	"encoding/json"
	"fmt"

	paycell "github.com/ozgur-soft/paycell.go/src"
)

// Pos bilgileri
const (
	envmode  = "TEST"                // Çalışma ortamı (Production : "PROD" - Test : "TEST")
	appname  = "PAYCELLTEST"         // Uygulama adı
	merchant = "9998"                // İşyeri numarası
	password = "PaycellTestPassword" // Şifre
	storekey = "PAYCELL12345"        // İşyeri anahtarı
)

func main() {
	api, req := paycell.Api(merchant, password, appname)
	api.Key = storekey
	api.SetMode(envmode)
	api.SetISDN("905591111177")           // Müşteri numarası (zorunlu)
	api.SetIPv4("127.0.0.1")              // Müşteri ip adresi (zorunlu)
	api.SetAmount("1.00", "TRY")          // Satış tutarı (zorunlu)
	req.SetCardNumber("4355084355084358") // Kart numarası (zorunlu)
	req.SetCardExpiry("12", "26")         // Son kullanma tarihi - AA,YY (zorunlu)
	req.SetCardCode("000")                // Kart arkasındaki 3 haneli numara (zorunlu)

	ctx := context.Background()
	if res, err := api.Auth(ctx, req); err == nil {
		pretty, _ := json.MarshalIndent(res.Provision, " ", " ")
		fmt.Println(string(pretty))
	} else {
		fmt.Println(err)
	}
}
```

```go
package main

import (
	"log"

	paycell "github.com/ozgur-soft/paycell.go/src"
)

func main() {
	api := paycell.Api("905591111177")
	api.SetMode("TEST")           // "PROD","TEST"
	api.SetIPAddress("127.0.0.1") // Müşteri ip adresi
	api.SetAmount("1.00", "TRY")  // Satış tutarı
	get := api.GetPaymentMethods()
	if get.PaymentMethods.Header.ResponseCode == "0" {
		if get.PaymentMethods.MobilePayment != nil {
			if !get.PaymentMethods.MobilePayment.IsDcbOpen {
				switch get.PaymentMethods.MobilePayment.IsEulaExpired {
				case true: // Sözleşmesi Güncel Olmayan Müşteri İçin
					if get.PaymentMethods.MobilePayment.EulaId != "" {
						open := api.OpenMobilePayment(get.PaymentMethods.MobilePayment.EulaId)
						if open.MobilePayment.Header.ResponseCode == "0" {
							log.Println("mobil ödeme açıldı")
						}
					}
				case false: // Sözleşmesi Güncel Olan Müşteri İçin
					if get.PaymentMethods.MobilePayment.SignedEulaId != "" {
						open := api.OpenMobilePayment(nil)
						if open.MobilePayment.Header.ResponseCode == "0" {
							log.Println("mobil ödeme açıldı")
						}
					}
				}
			}
			send := api.SendOTP()
			if send.OTP.Header.ResponseCode == "0" {
				if send.OTP.Token != nil {
					otp := ""
					validate := api.ValidateOTP(send.OTP.Token, otp)
					if validate.OTP.Header.ResponseCode == "0" {
						pay := api.Auth()
						if pay.Provision.Header.ResponseCode == "0" {
							log.Println("ödeme başarılı")
						}
					}
				}
			}
		}
	}
}
```