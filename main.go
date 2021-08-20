package main

import (
	"encoding/json"
	"fmt"

	paycell "github.com/ozgur-soft/paycell/src"
)

func main() {
	api := &paycell.API{"TEST"} // "PROD","TEST"
	request := new(paycell.Request)
	request.PaymentMethods.MSisdn = "5305289290"                // Müşteri telefon numarası
	request.PaymentMethods.Header.ClientIPAddress = "127.0.0.1" // Müşteri ip adresi
	response := api.GetPaymentMethods(request)
	pretty, _ := json.MarshalIndent(response.PaymentMethods, " ", "\t")
	fmt.Println(string(pretty))
}
