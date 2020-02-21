package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/lingfenghe/go-light-client/client"
	"math/big"
	rand2 "math/rand"
	"strconv"
	"time"
)

func main() {
	//createWeId
	fmt.Println("CreateWeId start---------------------------------------------------------------------------------------")
	publicKeyBigInt, privateKeyBigInt, weid, err1 := client.CreateWeId("39.106.69.186", "6001")
	if err1 == nil {
		fmt.Println("publicKeyBigInt =", publicKeyBigInt)
		fmt.Println("privateKeyBigInt =", privateKeyBigInt)
		fmt.Println("weid =", weid)
	} else {
		fmt.Println("err =", err1)
	}
	fmt.Println("CreateWeId end------------------------------------------------------------------------------------------")

    //registerAuthorityIssuer
	fmt.Println("RegisterAuthorityIssuer start---------------------------------------------------------------------------")
    contractDeployerPrivateKey := "66891022192008505617739700669391007653429796993194861158588523882789761146404"
	privateKey, _ := new(big.Int).SetString(contractDeployerPrivateKey, 10)
	rand2.Seed(time.Now().UnixNano())
    issuerName := "TestOrg" + strconv.Itoa(rand2.Int())
	err2 := client.RegisterAuthorityIssuer("39.106.69.186", "6001", weid, issuerName, privateKey)
	if err2 == nil {
		fmt.Println("issuerName :", issuerName, "has been register as authority issuer")
	} else {
		fmt.Println("err =", err2)
	}
	fmt.Println("RegisterAuthorityIssuer end------------------------------------------------------------------------------")

    //registerCpt
	fmt.Println("RegisterCpt start----------------------------------------------------------------------------------------")
	cptJsonSchema := `{"weid" : "Delegator WeID", "receiver": "Receiver WeID", "content": "Authorized content"}`
	privateKeyBytes := client.ConvertPrivateKeyBigIntToPrivateKeyBytes(privateKeyBigInt)
	cptSignatureBytes, _ := client.SignSignature(client.Hash([]byte(cptJsonSchema)), privateKeyBytes)
	cptSignature := base64.StdEncoding.EncodeToString(cptSignatureBytes)
	cptId, cptVersion, err3 := client.RegisterCpt("39.106.69.186", "6001", weid, cptJsonSchema, cptSignature)
	if err3 == nil {
		fmt.Println("cptId :", cptId, "cptVersion :", cptVersion, "has been created")
	}
	fmt.Println("RegisterCpt end------------------------------------------------------------------------------------------")

	//createCredentialPojo
	fmt.Println("CreateCredentialPojo start--------------------------------------------------------------------------------")
	claimMap := make(map[string]string)
	claimMap["weid"] = weid
	claimMap["receiver"] = weid
	claimMap["content"] = "b1016358-cf72-42be-9f4b-a18fca610fca"
	claimBytes, _ := json.Marshal(claimMap)
	claim := string(claimBytes)
	fmt.Println(claim)
	expirationDate := "2021-02-17T11:48:33Z"
	issuer := weid
	credentialEncodeResponse, credentialJsonStr, err4 := client.CreateCredentialPojo("39.106.69.186", "6001", claim, issuer, expirationDate, cptId, privateKeyBigInt)
	if err4 == nil {
		fmt.Println("credentialJsonStr =", credentialJsonStr)
		fmt.Println("cptId =", credentialEncodeResponse.RespBody.CptId)
		fmt.Println("issuanceDate =", credentialEncodeResponse.RespBody.IssuanceDate)
		fmt.Println("context =", credentialEncodeResponse.RespBody.Context)
		fmt.Println("claim =", credentialEncodeResponse.RespBody.Claim)
		fmt.Println("claim content =", credentialEncodeResponse.RespBody.Claim["content"])
		fmt.Println("claim receiver =", credentialEncodeResponse.RespBody.Claim["receiver"])
		fmt.Println("claim weid =", credentialEncodeResponse.RespBody.Claim["weid"])
		fmt.Println("id =", credentialEncodeResponse.RespBody.Id)
		fmt.Println("proof created =", credentialEncodeResponse.RespBody.Proof.Created)
		fmt.Println("proof creator =", credentialEncodeResponse.RespBody.Proof.Creator)
		fmt.Println("proof salt =", credentialEncodeResponse.RespBody.Proof.Salt)
		fmt.Println("proof salt content =", credentialEncodeResponse.RespBody.Proof.Salt["content"])
		fmt.Println("proof salt receiver =", credentialEncodeResponse.RespBody.Proof.Salt["receiver"])
		fmt.Println("proof salt weid =", credentialEncodeResponse.RespBody.Proof.Salt["weid"])
		fmt.Println("proof signatureValue =", credentialEncodeResponse.RespBody.Proof.SignatureValue)
		fmt.Println("type =", credentialEncodeResponse.RespBody.Type[0], credentialEncodeResponse.RespBody.Type[1])
		fmt.Println("issuer =", credentialEncodeResponse.RespBody.Issuer)
		fmt.Println("expirationDate =", credentialEncodeResponse.RespBody.ExpirationDate)
	} else {
		fmt.Println("err =", err4)
	}
	fmt.Println("CreateCredentialPojo end----------------------------------------------------------------------------------")

	//getWeIdDocument
	fmt.Println("GetWeIdDocument start-------------------------------------------------------------------------------------")
	weIdDocumentInvokeResponse, err5 := client.GetWeIdDocument("39.106.69.186", "6001", weid)
	if err5 == nil {
		fmt.Println("id =", weIdDocumentInvokeResponse.RespBody.Id)
		fmt.Println("created =", weIdDocumentInvokeResponse.RespBody.Created)
		fmt.Println("updated =", weIdDocumentInvokeResponse.RespBody.Updated)
		fmt.Println("publicKey =", weIdDocumentInvokeResponse.RespBody.PublicKey)
	} else {
		fmt.Println("err =", err5)
	}
	fmt.Println("GetWeIdDocument end----------------------------------------------------------------------------------------")

	//queryAuthorityIssuer
	fmt.Println("QueryAuthorityIssuer start----------------------------------------------------------------------------------")
	authorityIssuerInvokeResponse, err6 := client.QueryAuthorityIssuer("39.106.69.186", "6001", weid)
	if err6 == nil {
		fmt.Println("created =", authorityIssuerInvokeResponse.RespBody.Created)
		fmt.Println("accValue =", authorityIssuerInvokeResponse.RespBody.AccValue)
		fmt.Println("name =", authorityIssuerInvokeResponse.RespBody.Name)
		fmt.Println("weid =", authorityIssuerInvokeResponse.RespBody.WeId)
	} else {
		fmt.Println("err =", err6)
	}
	fmt.Println("QueryAuthorityIssuer end------------------------------------------------------------------------------------")

	//queryCpt
	fmt.Println("QueryCpt start----------------------------------------------------------------------------------------------")
	cptInvokeResponse, err7 := client.QueryCpt("39.106.69.186", "6001", cptId)
	if err7 == nil {
		fmt.Println("cptBaseInfo cptId =", cptInvokeResponse.RespBody.CptBaseInfo.CptId)
		fmt.Println("cptBaseInfo cptVersion =", cptInvokeResponse.RespBody.CptBaseInfo.CptVersion)
		fmt.Println("cptJsonSchema =", cptInvokeResponse.RespBody.CptJsonSchema)
		fmt.Println("cptJsonSchema schema =", cptInvokeResponse.RespBody.CptJsonSchema["$schema"])
		fmt.Println("cptJsonSchema content =", cptInvokeResponse.RespBody.CptJsonSchema["content"])
		fmt.Println("cptJsonSchema receiver =", cptInvokeResponse.RespBody.CptJsonSchema["receiver"])
		fmt.Println("cptJsonSchema type =", cptInvokeResponse.RespBody.CptJsonSchema["type"])
		fmt.Println("cptJsonSchema weid =", cptInvokeResponse.RespBody.CptJsonSchema["weid"])
		fmt.Println("metaData cptPublisher =", cptInvokeResponse.RespBody.MetaData.CptPublisher)
		fmt.Println("metaData cptSignature =", cptInvokeResponse.RespBody.MetaData.CptSignature)
		fmt.Println("metaData created =", cptInvokeResponse.RespBody.MetaData.Created)
		fmt.Println("metaData updated =", cptInvokeResponse.RespBody.MetaData.Updated)
	} else {
		fmt.Println("err =", err7)
	}
	fmt.Println("QueryCpt end-------------------------------------------------------------------------------------------------")

	//verifyCredentialPojo
	fmt.Println("VerifyCredentialPojo start-----------------------------------------------------------------------------------")
	verifyCredentialInvokeResponse, err8 := client.VerifyCredentialPojo("39.106.69.186", "6001", credentialJsonStr)
	if err8 == nil {
		fmt.Println(verifyCredentialInvokeResponse)
	} else {
		fmt.Println("err =", err8)
	}
	fmt.Println("VerifyCredentialPojo end-------------------------------------------------------------------------------------")

}


