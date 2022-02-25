#include <stdio.h>
#include <windows.h>
#include <winldap.h>

#define SECURITY_WIN32 1
#define DEBUG 2

#include <security.h>
#include <sspi.h>

BOOLEAN Queryclientcert(PLDAP Connection, PSecPkgContext_IssuerListInfoEx trusted_CAs, PCCERT_CONTEXT* ppCertificate) {
    return TRUE;
};

typedef struct berval BERVAL, *PBERVAL;

typedef enum _CREDSSP_SUBMIT_TYPE {
    CredsspPasswordCreds = 2,
    CredsspSchannelCreds = 4,
    CredsspCertificateCreds = 13,
    CredsspSubmitBufferBoth = 50,
    CredsspSubmitBufferBothOld = 51,
    CredsspCredEx = 100
} CREDSPP_SUBMIT_TYPE;

typedef struct _CREDSSP_CRED {
    CREDSPP_SUBMIT_TYPE Type;
    PVOID               pSchannelCred;
    PVOID               pSpnegoCred;
} CREDSSP_CRED, * PCREDSSP_CRED;

struct ldap_sasl_bind_params
{
    void* ld;
    const char* dn;
    const char* mech;
    struct bervalU* cred;
    PLDAPControlW* serverctrls;
    PLDAPControlW* clientctrls;
    int* msgid;
};

 struct ldap_sasl_bind_s_params
{
    void* ld;
    const char* dn;
    const char* mech;
    struct bervalU* cred;
    PLDAPControlW* serverctrls;
    PLDAPControlW* clientctrls;
    struct bervalU** servercred;
};

int wmain(int argc, TCHAR* argv[]) {
    if (argc < 5) {
        printf("\nUsage: %ws <user> <pass> <domain> <hostname>\n", (LPWSTR)argv[0]);
        exit(1);
    }

    
    LDAP* ld;
    int rc = 0;
    const int version = LDAP_VERSION3;
    SEC_WINNT_AUTH_IDENTITY wincreds;
    CREDSSP_CRED wincredssp;
    struct berval* servresp = NULL;
    SECURITY_STATUS res;
    CredHandle credhandle;
    CtxtHandle newhandle = CtxtHandle();
    SecBufferDesc OutBuffDesc;
    SecBuffer OutSecBuff;
    SecBufferDesc InBuffDesc;
    SecBuffer InSecBuff;
    SecPkgContext_ConnectionInfo sslInfo;
    unsigned long contextattr;
    LONG lv = 0;
    QUERYCLIENTCERT Queryclientcert;

    
    ZeroMemory(&wincreds, sizeof(wincreds));
    ZeroMemory(&wincredssp, sizeof(wincredssp));

    // Set credential information
    wincreds.User = (unsigned short*)argv[1];
    wincreds.UserLength = 8;
    wincreds.Password = (unsigned short*)argv[2];
    wincreds.PasswordLength = 9;
    wincreds.Domain = (unsigned short*)argv[3];
    wincreds.DomainLength = 10;
    wincreds.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

    // Set credential information for CredSSP
    wincredssp.Type = CREDSPP_SUBMIT_TYPE::CredsspPasswordCreds;
    wincredssp.pSchannelCred = nullptr;
    wincredssp.pSpnegoCred = nullptr;

    LPWSTR spn = (LPWSTR)argv[4];


    res = AcquireCredentialsHandleW(NULL, (LPWSTR)L"WDigest", SECPKG_CRED_OUTBOUND| SECPKG_CRED_INBOUND,
    //res = AcquireCredentialsHandleW(NULL, (LPWSTR)UNISP_NAME, SECPKG_CRED_OUTBOUND,
        NULL, &wincreds, NULL, NULL, &credhandle, NULL);

    if (res != SEC_E_OK){
        printf("FUCCKKK!!!\n");
        exit(1);
    }

    // Buffer for the output token.
    OutBuffDesc.ulVersion = SECBUFFER_VERSION;
    OutBuffDesc.cBuffers = 1;
    OutBuffDesc.pBuffers = &OutSecBuff;

    OutSecBuff.BufferType = SECBUFFER_TOKEN;
    OutSecBuff.pvBuffer = NULL;

    ld = ldap_sslinit(spn, LDAP_SSL_PORT, 1);
    rc = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, (void*)&version);
    // rc = ldap_set_option(ld, LDAP_OPT_, LDAP_OPT_X_TLS_NEVER);

    //  Verify that SSL is enabled on the connection.
    //  (returns LDAP_OPT_ON/_OFF).
    printf("Checking if SSL is enabled\n");
    rc = ldap_get_option(ld, LDAP_OPT_SSL, (void*)&lv);
    if (rc != LDAP_SUCCESS)
        exit(1);

    //  If SSL is not enabled, enable it.
    if ((void*)lv == LDAP_OPT_ON)
        printf("SSL is enabled\n");
    else
    {
        printf("SSL not enabled. SSL being enabled...\n");
        rc = ldap_set_option(ld, LDAP_OPT_SSL, LDAP_OPT_ON);
        // Dsiable Certificate Validation
        rc = ldap_set_option(ld, LDAP_OPT_SERVER_CERTIFICATE, Queryclientcert);
        // Disable Signing
        ldap_set_option(ld, LDAP_OPT_SIGN, LDAP_OPT_OFF);
        // Disable encryption
        ldap_set_option(ld, LDAP_OPT_ENCRYPT, LDAP_OPT_OFF);
        if (rc != LDAP_SUCCESS)
            exit(1);
    }

    rc = ldap_connect(ld, NULL); // Need to connect before SASL bind!
    
    if (rc == LDAP_SUCCESS)
        printf("ldap_connect succeeded \n");
    else
    {
        printf("ldap_connect failed with 0x%x.\n", rc);
        exit(1);
    }

    int counter = 1;
    do {
        printf("--- Auth Step %u\n", counter);
        counter++;
        if (servresp != NULL) {
#if DEBUG == 2
            printf("Server Response is not NULL\n");
#endif
            InBuffDesc.ulVersion = SECBUFFER_VERSION;
            InBuffDesc.cBuffers = 1;
            InBuffDesc.pBuffers = &InSecBuff;

            /* The digest-challenge will be passed as an input buffer to
            InitializeSecurityContext function */
            InSecBuff.cbBuffer = servresp->bv_len;
            InSecBuff.BufferType = SECBUFFER_TOKEN;
            InSecBuff.pvBuffer = servresp->bv_val;

#if DEBUG == 2
            printf("Server auth data: %u\n", servresp->bv_len);
            if (servresp->bv_val != NULL) {
                printf("Auth data: \n");

                int i;
                for (i = 0; i < servresp->bv_len; i++)
                {
                    if (i > 0) printf(":");
                    printf("%02X", servresp->bv_val[i]);
                }
                printf("\n");
            }
#endif

            /* The OutBuffDesc will contain the digest-response. */
            res = InitializeSecurityContext(
                &credhandle, 
                &newhandle, 
                spn, 
                ISC_REQ_EXTENDED_ERROR | ISC_REQ_MUTUAL_AUTH | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_USE_SUPPLIED_CREDS | ISC_REQ_MANUAL_CRED_VALIDATION,
                0, 
                0, 
                &InBuffDesc, 
                0, 
                &newhandle, 
                &OutBuffDesc, 
                &contextattr, 
                NULL
            );
        }
        else {
#if DEBUG == 2
            printf("Server Response is NULL\n");
#endif
            res = InitializeSecurityContext(
                &credhandle, 
                NULL, 
                spn, 
                ISC_REQ_EXTENDED_ERROR | ISC_REQ_MUTUAL_AUTH | ISC_REQ_USE_SUPPLIED_CREDS | ISC_REQ_MANUAL_CRED_VALIDATION, 
                0, 
                0, 
                NULL, 
                0, 
                &newhandle, 
                &OutBuffDesc, 
                &contextattr, 
                NULL
            );
        }

        switch (res) {
        case SEC_I_COMPLETE_NEEDED:
        case SEC_I_COMPLETE_AND_CONTINUE:
        case SEC_E_OK:
        case SEC_I_CONTINUE_NEEDED:
            break;
        case SEC_E_INVALID_HANDLE:
            return -2;
        case SEC_E_INVALID_TOKEN:
            return -1;
        default:
            break;
        }

        PBERVAL cred = (PBERVAL)malloc(sizeof(BERVAL));
        if (cred == NULL) {
            printf("Couldn't Allocate BERVAL\n");
            exit(1);
        }else{
            cred->bv_len = OutSecBuff.cbBuffer;
            /* The digest-response will be passed to the server
            as credential after the second (loop)run. */
            cred->bv_val = (char*)OutSecBuff.pvBuffer;
        }
#if DEBUG >= 1

        printf("Length of auth data: %u\n", cred->bv_len);
        if (cred->bv_val != NULL){
            printf("Auth data: \n");

            int i;
            for (i = 0; i < cred->bv_len; i++)
            {
                if (i > 0) printf(":");
                printf("%02X", cred->bv_val[i]);
            }
            printf("\n");
        }
#endif
        // The servresp will contain the digest-challange after the first call.
        // rc = ldap_sasl_bind_sW(ld, (LPWSTR)L"", (LPWSTR)L"GSS-SPNEGO", cred, NULL, NULL, &servresp);
        // rc = ldap_sasl_bind_sW(ld, (LPWSTR)L"", (LPWSTR)L"DIGEST-MD5", &cred, NULL, NULL, &servresp);

        

        rc = ldap_bind_sW(ld, (LPWSTR)L"", (LPWSTR)&wincreds, LDAP_AUTH_SICILY);
        ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &res);
        free(cred);
    } while (res == LDAP_SASL_BIND_IN_PROGRESS);

        if (rc != LDAP_SUCCESS) {
            printf("Bind failed with 0x%x\n", rc);
        }
        else {
            printf("Bind succeeded\n");
        }


        return 0;
}
