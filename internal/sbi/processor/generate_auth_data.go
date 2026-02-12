package processor

import (
	cryptoRand "crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"math/rand"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	Nudr_DataRepository "github.com/free5gc/openapi/udr/DataRepository"
	"github.com/free5gc/udm/internal/logger"
	"github.com/free5gc/udm/internal/util"
	"github.com/free5gc/udm/pkg/suci"
	"github.com/free5gc/util/metrics/sbi"
	"github.com/free5gc/util/milenage"
	"github.com/free5gc/util/ueauth"
)

const (
	SqnMAx    int64 = 0xFFFFFFFFFFFF
	ind       int64 = 32
	keyStrLen int   = 32
	opStrLen  int   = 32
	opcStrLen int   = 32
)

const (
	authenticationRejected string = "AUTHENTICATION_REJECTED"
	resyncAMF              string = "0000"
)

func (p *Processor) aucSQN(opc, k, auts, rand []byte) ([]byte, []byte) {
	logger.UeauLog.Debugf("[SQN-Resync] aucSQN called: AUTS=[%x], RAND=[%x]", auts, rand)
	logger.UeauLog.Debugf("[SQN-Resync] aucSQN: AUTS[0:6] (encrypted SQN) = [%x]", auts[0:6])
	logger.UeauLog.Debugf("[SQN-Resync] aucSQN: AUTS[6:14] (MAC-S from UE) = [%x]", auts[6:14])

	// ValidateAUTS internally:
	// 1. Computes AK* = f5*(K, RAND) to de-conceal SQN
	// 2. SQNms = AUTS[0:6] XOR AK*
	// 3. Computes XMAC-S = f1*(K, SQNms, RAND, AMF=0x0000)
	// 4. Verifies XMAC-S == AUTS[6:14]
	SQNms, _, err := milenage.ValidateAUTS(opc, k, rand, auts)
	if err != nil {
		logger.UeauLog.Errorf("[SQN-Resync] aucSQN: ValidateAUTS FAILED: %v", err)
		return nil, nil
	}

	logger.UeauLog.Infof("[SQN-Resync] aucSQN: MAC-S verified OK")
	logger.UeauLog.Infof("[SQN-Resync] aucSQN: Decrypted SQNms = [%x] (decimal %d)",
		SQNms, new(big.Int).SetBytes(SQNms).Int64())

	macS := auts[6:14]
	return SQNms, macS
}

func (p *Processor) strictHex(ss string, n int) string {
	l := len(ss)
	if l < n {
		return strings.Repeat("0", n-l) + ss
	} else {
		return ss[l-n : l]
	}
}

func (p *Processor) ConfirmAuthDataProcedure(c *gin.Context,
	authEvent models.AuthEvent,
	supi string,
) {
	ctx, pd, err := p.Context().GetTokenCtx(models.ServiceName_NUDR_DR, models.NrfNfManagementNfType_UDR)
	if err != nil {
		c.Set(sbi.IN_PB_DETAILS_CTX_STR, pd.Cause)
		c.JSON(int(pd.Status), pd)
		return
	}
	var createAuthStatusRequest Nudr_DataRepository.CreateAuthenticationStatusRequest
	createAuthStatusRequest.AuthEvent = &authEvent
	createAuthStatusRequest.UeId = &supi

	client, err := p.Consumer().CreateUDMClientToUDR(supi)
	if err != nil {
		problemDetails := openapi.ProblemDetailsSystemFailure(err.Error())
		c.Set(sbi.IN_PB_DETAILS_CTX_STR, problemDetails.Cause)
		c.JSON(int(problemDetails.Status), problemDetails)
		return
	}

	_, err = client.AuthenticationStatusDocumentApi.CreateAuthenticationStatus(
		ctx, &createAuthStatusRequest)
	if err != nil {
		apiError, ok := err.(openapi.GenericOpenAPIError)
		if ok {
			c.Set(sbi.IN_PB_DETAILS_CTX_STR, http.StatusText(apiError.ErrorStatus))
			c.JSON(apiError.ErrorStatus, apiError.RawBody)
			return
		}
		logger.UeauLog.Errorln("ConfirmAuth err:", err.Error())
		problemDetails := openapi.ProblemDetailsSystemFailure(err.Error())
		c.Set(sbi.IN_PB_DETAILS_CTX_STR, problemDetails.Cause)
		c.JSON(int(problemDetails.Status), problemDetails)
		return
	}

	c.JSON(http.StatusCreated, gin.H{})
}

func (p *Processor) GenerateAuthDataProcedure(
	c *gin.Context,
	authInfoRequest models.AuthenticationInfoRequest,
	supiOrSuci string,
) {
	ctx, pd, err := p.Context().GetTokenCtx(models.ServiceName_NUDR_DR, models.NrfNfManagementNfType_UDR)
	if err != nil {
		c.Set(sbi.IN_PB_DETAILS_CTX_STR, pd.Cause)
		c.JSON(int(pd.Status), pd)
		return
	}
	logger.UeauLog.Traceln("In GenerateAuthDataProcedure")

	response := &models.UdmUeauAuthenticationInfoResult{}
	rand.New(rand.NewSource(time.Now().UnixNano()))
	supi, err := suci.ToSupi(supiOrSuci, p.Context().SuciProfiles)
	if err != nil {
		problemDetails := &models.ProblemDetails{
			Status: http.StatusForbidden,
			Cause:  authenticationRejected,
			Detail: err.Error(),
		}

		logger.UeauLog.Errorln("suciToSupi error: ", err.Error())
		c.Set(sbi.IN_PB_DETAILS_CTX_STR, problemDetails.Cause)
		c.JSON(int(problemDetails.Status), problemDetails)
		return
	}

	logger.UeauLog.Tracef("supi conversion => [%s]", supi)

	client, err := p.Consumer().CreateUDMClientToUDR(supi)
	if err != nil {
		problemDetails := openapi.ProblemDetailsSystemFailure(err.Error())
		c.Set(sbi.IN_PB_DETAILS_CTX_STR, problemDetails.Cause)
		c.JSON(int(problemDetails.Status), problemDetails)
		return
	}
	var queryAuthSubsDataRequest Nudr_DataRepository.QueryAuthSubsDataRequest
	queryAuthSubsDataRequest.UeId = &supi

	authSubs, err := client.AuthenticationDataDocumentApi.QueryAuthSubsData(ctx, &queryAuthSubsDataRequest)
	if err != nil {
		logger.ProcLog.Errorf("Error on QueryAuthSubsData: %+v", err)
		apiError, ok := err.(openapi.GenericOpenAPIError)
		if ok {
			c.Set(sbi.IN_PB_DETAILS_CTX_STR, http.StatusText(apiError.ErrorStatus))
			c.JSON(apiError.ErrorStatus, apiError.RawBody)
			switch apiError.ErrorStatus {
			case http.StatusNotFound:
				logger.UeauLog.Warnf("Return from UDR QueryAuthSubsData error")
			default:
				logger.UeauLog.Errorln("Return from UDR QueryAuthSubsData error")
			}
			return
		}
		problemDetails := openapi.ProblemDetailsSystemFailure(err.Error())
		c.Set(sbi.IN_PB_DETAILS_CTX_STR, problemDetails.Cause)
		c.JSON(int(problemDetails.Status), problemDetails)
		return
	}

	/*
		K, RAND, CK, IK: 128 bits (16 bytes) (hex len = 32)
		SQN, AK: 48 bits (6 bytes) (hex len = 12) TS33.102 - 6.3.2
		AMF: 16 bits (2 bytes) (hex len = 4) TS33.102 - Annex H
	*/

	hasOPC := false
	var kStr, opcStr string
	var k, opc []byte
	if authSubs.AuthenticationSubscription.EncPermanentKey != "" {
		kStr = authSubs.AuthenticationSubscription.EncPermanentKey
		if len(kStr) == keyStrLen {
			k, err = hex.DecodeString(kStr)
			if err != nil {
				logger.UeauLog.Errorln("err:", err)
			}
		} else {
			problemDetails := &models.ProblemDetails{
				Status: http.StatusForbidden,
				Cause:  authenticationRejected,
				Detail: "len(kStr) != keyStrLen",
			}

			logger.UeauLog.Errorln("kStr length is ", len(kStr))
			c.Set(sbi.IN_PB_DETAILS_CTX_STR, problemDetails.Cause)
			c.JSON(int(problemDetails.Status), problemDetails)
			return
		}
	} else {
		problemDetails := &models.ProblemDetails{
			Status: http.StatusForbidden,
			Cause:  authenticationRejected,
			Detail: "EncPermanentKey == ''",
		}

		logger.UeauLog.Errorln("Nil PermanentKey")
		c.Set(sbi.IN_PB_DETAILS_CTX_STR, problemDetails.Cause)
		c.JSON(int(problemDetails.Status), problemDetails)
		return
	}

	if authSubs.AuthenticationSubscription.EncOpcKey != "" {
		opcStr = authSubs.AuthenticationSubscription.EncOpcKey
		if len(opcStr) == opcStrLen {
			opc, err = hex.DecodeString(opcStr)
			if err != nil {
				logger.UeauLog.Errorln("err:", err)
			} else {
				hasOPC = true
			}
		} else {
			logger.UeauLog.Errorln("opcStr length is ", len(opcStr))
		}
	} else {
		logger.UeauLog.Infoln("Nil Opc")
	}

	if !hasOPC {
		problemDetails := &models.ProblemDetails{
			Status: http.StatusForbidden,
			Cause:  authenticationRejected,
		}
		c.Set(sbi.IN_PB_DETAILS_CTX_STR, problemDetails.Cause)
		c.JSON(int(problemDetails.Status), problemDetails)
		return
	}

	sqnStr := p.strictHex(authSubs.AuthenticationSubscription.SequenceNumber.Sqn, 12)
	sqn, err := hex.DecodeString(sqnStr)
	if err != nil {
		problemDetails := &models.ProblemDetails{
			Status: http.StatusForbidden,
			Cause:  authenticationRejected,
			Detail: err.Error(),
		}

		logger.UeauLog.Errorln("err:", err)
		c.Set(sbi.IN_PB_DETAILS_CTX_STR, problemDetails.Cause)
		c.JSON(int(problemDetails.Status), problemDetails)
		return
	}

	// ── Auth flow log: credentials loaded from DB ──
	isResync := authInfoRequest.ResynchronizationInfo != nil
	logger.UeauLog.Infof("[Auth] ── Begin GenerateAuthData for %s (resync=%v) ──", supiOrSuci, isResync)
	logger.UeauLog.Infof("[Auth] K=[%s], OPC=[%s]", kStr, opcStr)
	logger.UeauLog.Infof("[Auth] DB SQN (before)=[%s] (decimal %d)", sqnStr, new(big.Int).SetBytes(sqn).Int64())

	RAND := make([]byte, 16)
	_, err = cryptoRand.Read(RAND)
	if err != nil {
		problemDetails := &models.ProblemDetails{
			Status: http.StatusForbidden,
			Cause:  authenticationRejected,
			Detail: err.Error(),
		}

		logger.UeauLog.Errorln("err:", err)
		c.Set(sbi.IN_PB_DETAILS_CTX_STR, problemDetails.Cause)
		c.JSON(int(problemDetails.Status), problemDetails)
		return
	}

	amfStr := p.strictHex(authSubs.AuthenticationSubscription.AuthenticationManagementField, 4)
	AMF, err := hex.DecodeString(amfStr)
	if err != nil {
		problemDetails := &models.ProblemDetails{
			Status: http.StatusForbidden,
			Cause:  authenticationRejected,
			Detail: err.Error(),
		}

		logger.UeauLog.Errorln("err:", err)
		c.Set(sbi.IN_PB_DETAILS_CTX_STR, problemDetails.Cause)
		c.JSON(int(problemDetails.Status), problemDetails)
		return
	}

	logger.UeauLog.Infof("[Auth] RAND=[%x], AMF=[%x]", RAND, AMF)

	// re-synchronization
	if authInfoRequest.ResynchronizationInfo != nil {
		logger.UeauLog.Infof("[SQN-Resync] ══════════════════════════════════════")
		logger.UeauLog.Infof("[SQN-Resync] Re-synchronization triggered for %s", supiOrSuci)

		Auts, deCodeErr := hex.DecodeString(authInfoRequest.ResynchronizationInfo.Auts)
		if deCodeErr != nil {
			problemDetails := &models.ProblemDetails{
				Status: http.StatusForbidden,
				Cause:  authenticationRejected,
				Detail: deCodeErr.Error(),
			}

			logger.UeauLog.Errorln("err:", deCodeErr)
			c.Set(sbi.IN_PB_DETAILS_CTX_STR, problemDetails.Cause)
			c.JSON(int(problemDetails.Status), problemDetails)
			return
		}

		randHex, deCodeErr := hex.DecodeString(authInfoRequest.ResynchronizationInfo.Rand)
		if deCodeErr != nil {
			problemDetails := &models.ProblemDetails{
				Status: http.StatusForbidden,
				Cause:  authenticationRejected,
				Detail: deCodeErr.Error(),
			}

			logger.UeauLog.Errorln("err:", deCodeErr)
			c.Set(sbi.IN_PB_DETAILS_CTX_STR, problemDetails.Cause)
			c.JSON(int(problemDetails.Status), problemDetails)
			return
		}

		logger.UeauLog.Infof("[SQN-Resync] AUTS from UE      = [%x] (14 bytes)", Auts)
		logger.UeauLog.Infof("[SQN-Resync]   AUTS[0:6]  (encrypted SQN = SQNms XOR AK*) = [%x]", Auts[0:6])
		logger.UeauLog.Infof("[SQN-Resync]   AUTS[6:14] (MAC-S = f1*)                   = [%x]", Auts[6:])
		logger.UeauLog.Infof("[SQN-Resync] RAND (from failed auth) = [%x]", randHex)
		logger.UeauLog.Infof("[SQN-Resync] Decrypting: AK* = f5*(K, RAND), SQNms = AUTS[0:6] XOR AK*")

		SQNms, macS := p.aucSQN(opc, k, Auts, randHex)
		if reflect.DeepEqual(macS, Auts[6:]) {
			logger.UeauLog.Infof("[SQN-Resync] ✓ MAC-S verified: f1*(SQNms, RAND, AMF=0x0000) matches AUTS[6:14]")
			logger.UeauLog.Infof("[SQN-Resync] Decrypted SQNms = [%x] (decimal %d)",
				SQNms, new(big.Int).SetBytes(SQNms).Int64())
			logger.UeauLog.Infof("[SQN-Resync] DB SQN was      = [%s] (decimal %d) ← stale/mismatched",
				sqnStr, new(big.Int).SetBytes(sqn).Int64())

			_, err = cryptoRand.Read(RAND)
			if err != nil {
				problemDetails := &models.ProblemDetails{
					Status: http.StatusForbidden,
					Cause:  authenticationRejected,
					Detail: err.Error(),
				}

				logger.UeauLog.Errorln("err:", err)
				c.Set(sbi.IN_PB_DETAILS_CTX_STR, problemDetails.Cause)
				c.JSON(int(problemDetails.Status), problemDetails)
				return
			}

			// Re-sync: use SQN decoded from UE's AUTS (SQNms)
			// The post-resync increment block below will add +1
			sqnStr = hex.EncodeToString(SQNms)
			sqnStr = p.strictHex(sqnStr, 12)
			logger.UeauLog.Infof("[SQN-Resync] Using UE's SQNms = [%s] as base (will increment +1 below)", sqnStr)
			logger.UeauLog.Infof("[SQN-Resync] New RAND for auth vector = [%x]", RAND)
			logger.UeauLog.Infof("[SQN-Resync] ══════════════════════════════════════")
		} else {
			logger.UeauLog.Errorf("[SQN-Resync] ✗ MAC-S verification FAILED for %s (supi=%s)", supiOrSuci, supi)
			logger.UeauLog.Errorf("[SQN-Resync]   Computed MAC-S = [%x]", macS)
			logger.UeauLog.Errorf("[SQN-Resync]   AUTS MAC-S     = [%x]", Auts[6:])
			logger.UeauLog.Errorf("[SQN-Resync]   Decrypted SQN  = [%x]", SQNms)
			logger.UeauLog.Errorf("[SQN-Resync] ══════════════════════════════════════")
			problemDetails := &models.ProblemDetails{
				Status: http.StatusForbidden,
				Cause:  "modification is rejected",
			}
			c.Set(sbi.IN_PB_DETAILS_CTX_STR, problemDetails.Cause)
			c.JSON(int(problemDetails.Status), problemDetails)
			return
		}
	}

	// ── Increment SQN ──
	sqnBeforeIncrement := sqnStr
	bigSQN := big.NewInt(0)
	sqn, err = hex.DecodeString(sqnStr)
	if err != nil {
		problemDetails := &models.ProblemDetails{
			Status: http.StatusForbidden,
			Cause:  authenticationRejected,
			Detail: err.Error(),
		}

		logger.UeauLog.Errorln("err:", err)
		c.Set(sbi.IN_PB_DETAILS_CTX_STR, problemDetails.Cause)
		c.JSON(int(problemDetails.Status), problemDetails)
		return
	}

	bigSQN.SetString(sqnStr, 16)

	bigInc := big.NewInt(1)
	bigSQN = bigInc.Add(bigSQN, bigInc)

	SQNheStr := fmt.Sprintf("%x", bigSQN)
	SQNheStr = p.strictHex(SQNheStr, 12)

	logger.UeauLog.Infof("[Auth] SQN increment: [%s] → [%s] (decimal %d → %d)",
		sqnBeforeIncrement, SQNheStr,
		new(big.Int).SetBytes(sqn).Int64(),
		bigSQN.Int64())

	patchItemArray := []models.PatchItem{
		{
			Op:   models.PatchOperation_REPLACE,
			Path: "/sequenceNumber",
			Value: models.SequenceNumber{
				Sqn: SQNheStr,
			},
		},
	}

	logger.ProcLog.Infoln("ModifyAuthenticationSubscriptionRequest: ", patchItemArray)

	var modifyAuthenticationSubscriptionRequest Nudr_DataRepository.ModifyAuthenticationSubscriptionRequest
	modifyAuthenticationSubscriptionRequest.UeId = &supi
	modifyAuthenticationSubscriptionRequest.PatchItem = patchItemArray
	_, err = client.AuthenticationSubscriptionDocumentApi.ModifyAuthenticationSubscription(
		ctx, &modifyAuthenticationSubscriptionRequest)
	if err != nil {
		problemDetails := &models.ProblemDetails{
			Status: http.StatusForbidden,
			Cause:  "modification is rejected ",
			Detail: err.Error(),
		}

		logger.UeauLog.Errorln("update sqn error:", err)
		c.Set(sbi.IN_PB_DETAILS_CTX_STR, problemDetails.Cause)
		c.JSON(int(problemDetails.Status), problemDetails)
		return
	}

	logger.UeauLog.Infof("[Auth] SQN saved to DB: [%s]", SQNheStr)

	// Update sqn bytes to the incremented value so auth vector uses SQN+1
	sqn, err = hex.DecodeString(SQNheStr)
	if err != nil {
		logger.UeauLog.Errorln("err decoding incremented SQN:", err)
	}

	// Run milenage
	macA, macS := make([]byte, 8), make([]byte, 8)
	CK, IK := make([]byte, 16), make([]byte, 16)
	RES := make([]byte, 8)
	AK, AKstar := make([]byte, 6), make([]byte, 6)

	// Generate macA, macS
	err = util.MilenageF1(opc, k, RAND, sqn, AMF, macA, macS)
	if err != nil {
		logger.UeauLog.Errorln("milenage F1 err:", err)
	}

	// Generate RES, CK, IK, AK, AKstar
	err = util.MilenageF2345(opc, k, RAND, RES, CK, IK, AK, AKstar)
	if err != nil {
		logger.UeauLog.Errorln("milenage F2345 err:", err)
	}

	// Generate AUTN
	SQNxorAK := make([]byte, 6)
	for i := 0; i < len(sqn); i++ {
		SQNxorAK[i] = sqn[i] ^ AK[i]
	}
	AUTN := append(append(SQNxorAK, AMF...), macA...)

	logger.UeauLog.Infof("[Auth] ── Auth vector generated ──")
	logger.UeauLog.Infof("[Auth]   SQN used     = [%x] (decimal %d)", sqn, new(big.Int).SetBytes(sqn).Int64())
	logger.UeauLog.Infof("[Auth]   RAND         = [%x]", RAND)
	logger.UeauLog.Infof("[Auth]   AK (f5)      = [%x]", AK)
	logger.UeauLog.Infof("[Auth]   SQN XOR AK   = [%x]  ← encrypted SQN in AUTN", SQNxorAK)
	logger.UeauLog.Infof("[Auth]   MAC-A (f1)   = [%x]", macA)
	logger.UeauLog.Infof("[Auth]   AUTN         = [%x]  (SQN^AK || AMF || MAC-A)", AUTN)
	logger.UeauLog.Infof("[Auth]   XRES         = [%x]", RES)
	logger.UeauLog.Infof("[Auth] ── End auth for %s ──", supiOrSuci)

	var av models.AuthenticationVector
	if authSubs.AuthenticationSubscription.AuthenticationMethod == models.AuthMethod__5_G_AKA {
		response.AuthType = models.UdmUeauAuthType__5_G_AKA

		// derive XRES*
		key := append(CK, IK...)
		FC := ueauth.FC_FOR_RES_STAR_XRES_STAR_DERIVATION
		P0 := []byte(authInfoRequest.ServingNetworkName)
		P1 := RAND
		P2 := RES

		kdfValForXresStar, err := ueauth.GetKDFValue(
			key, FC, P0, ueauth.KDFLen(P0), P1, ueauth.KDFLen(P1), P2, ueauth.KDFLen(P2))
		if err != nil {
			logger.UeauLog.Errorf("Get kdfValForXresStar err: %+v", err)
		}
		xresStar := kdfValForXresStar[len(kdfValForXresStar)/2:]

		// derive Kausf
		FC = ueauth.FC_FOR_KAUSF_DERIVATION
		P0 = []byte(authInfoRequest.ServingNetworkName)
		P1 = SQNxorAK
		kdfValForKausf, err := ueauth.GetKDFValue(key, FC, P0, ueauth.KDFLen(P0), P1, ueauth.KDFLen(P1))
		if err != nil {
			logger.UeauLog.Errorf("Get kdfValForKausf err: %+v", err)
		}

		// Fill in rand, xresStar, autn, kausf
		av.Rand = hex.EncodeToString(RAND)
		av.XresStar = hex.EncodeToString(xresStar)
		av.Autn = hex.EncodeToString(AUTN)
		av.Kausf = hex.EncodeToString(kdfValForKausf)
		av.AvType = models.AvType__5_G_HE_AKA
	} else { // EAP-AKA'
		response.AuthType = models.UdmUeauAuthType_EAP_AKA_PRIME
		// derive CK' and IK'
		key := append(CK, IK...)
		FC := ueauth.FC_FOR_CK_PRIME_IK_PRIME_DERIVATION
		P0 := []byte(authInfoRequest.ServingNetworkName)
		P1 := SQNxorAK
		kdfVal, err := ueauth.GetKDFValue(key, FC, P0, ueauth.KDFLen(P0), P1, ueauth.KDFLen(P1))
		if err != nil {
			logger.UeauLog.Errorf("Get kdfVal err: %+v", err)
		}

		ckPrime := kdfVal[:len(kdfVal)/2]
		ikPrime := kdfVal[len(kdfVal)/2:]

		// Fill in rand, xres, autn, ckPrime, ikPrime
		av.Rand = hex.EncodeToString(RAND)
		av.Xres = hex.EncodeToString(RES)
		av.Autn = hex.EncodeToString(AUTN)
		av.CkPrime = hex.EncodeToString(ckPrime)
		av.IkPrime = hex.EncodeToString(ikPrime)
		av.AvType = models.AvType_EAP_AKA_PRIME
	}

	response.AuthenticationVector = &av
	response.Supi = supi
	c.JSON(http.StatusOK, response)
}
