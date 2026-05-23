/* Stub header for ldsca.dll build.
   UA-LDS\settings.c does `#include <opcua_p_crypto.h>` and uses the
   OpcUa_SecurityPolicy_* string constants below (verbatim copies from the
   real opcua_p_crypto.h in UA-LDS\stack).  Including the real header would
   drag in the entire OPC UA AnsiC stack just to validate INI entries that
   never get touched by the custom actions.  String constants are stable
   per OPC UA spec, so the copy is safe. */
#ifndef __LDSCA_STUB_OPCUA_P_CRYPTO_H__
#define __LDSCA_STUB_OPCUA_P_CRYPTO_H__

#define OpcUa_SecurityPolicy_None                "http://opcfoundation.org/UA/SecurityPolicy#None"
#define OpcUa_SecurityPolicy_Basic128Rsa15       "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15"
#define OpcUa_SecurityPolicy_Basic256            "http://opcfoundation.org/UA/SecurityPolicy#Basic256"
#define OpcUa_SecurityPolicy_Basic256Sha256      "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"
#define OpcUa_SecurityPolicy_Aes128Sha256RsaOaep "http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep"
#define OpcUa_SecurityPolicy_Aes256Sha256RsaPss  "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss"

#endif
