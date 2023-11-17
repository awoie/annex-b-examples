const { default: base64url } = require('base64url');
const jose = require('node-jose');
const fs = require('fs');

async function main() {

  const static_wallet_metadata = {
    "issuer":"https://self-issued.me/v2",
    "authorization_endpoint":"mdoc-openid4vp://",
    "response_types_supported":[
      "vp_token"
    ],
    "vp_formats_supported":{
      "mso_mdoc":{}
    },
    "client_id_schemes_supported":[
      "x509_san_dns"
    ],
    "authorization_encryption_alg_values_supported":[ "ECDH-ES" ], 
    "authorization_encryption_enc_values_supported":[ "A256GCM" ]
  };

  const presentation_definition = {
    "id":"mDL-sample-req",
    "input_descriptors":[
      {
        "id":"org.iso.18013.5.1.mDL ",
        "format":{
          "mso_mdoc":{
            "alg":[
              "ES256",
              "ES384",
              "ES512",
              "EdDSA",
              "ESB256",
              "ESB320",
              "ESB384",
              "ESB512"
            ]
          }
        },
        "constraints":{
          "fields":[
            {
              "path":[
                "$['org.iso.18013.5.1']['birth_date']"
              ],
              "intent_to_retain":false
            },
            {
              "path":[
                "$['org.iso.18013.5.1']['document_number']"
              ],
              "intent_to_retain":false
            },
            {
              "path":[
                "$['org.iso.18013.5.1']['driving_privileges']"
              ],
              "intent_to_retain":false
            },
            {
              "path":[
                "$['org.iso.18013.5.1']['expiry_date']"
              ],
              "intent_to_retain":false
            },
            {
              "path":[
                "$['org.iso.18013.5.1']['family_name']"
              ],
              "intent_to_retain":false
            },
            {
              "path":[
                "$['org.iso.18013.5.1']['given_name']"
              ],
              "intent_to_retain":false
            },
            {
              "path":[
                "$['org.iso.18013.5.1']['issue_date']"
              ],
              "intent_to_retain":false
            },
            {
              "path":[
                "$['org.iso.18013.5.1']['issuing_authority']"
              ],
              "intent_to_retain":false
            },
            {
              "path":[
                "$['org.iso.18013.5.1']['issuing_country']"
              ],
              "intent_to_retain":false
            },
            {
              "path":[
                "$['org.iso.18013.5.1']['portrait']"
              ],
              "intent_to_retain":false
            },
            {
              "path":[
                "$['org.iso.18013.5.1']['un_distinguishing_sign']"
              ],
              "intent_to_retain":false
            }
          ],
          "limit_disclosure":"required"
        }
      }
    ]
  };

  const ephemeral_private_key_reader = {
    "kty":"EC",
    "d":"_Hc7lRd1Zt8sDAb1-pCgI9qS3oobKNa-mjRDhaKjH90",
    "use":"enc",
    "crv":"P-256",
    "x":"xVLtZaPPK-xvruh1fEClNVTR6RCZBsQai2-DrnyKkxg",
    "y":"-5-QtFqJqGwOjEL3Ut89nrE0MeaUp5RozksKHpBiyw0",
    "alg":"ECDH-ES",
    "kid":"P8p0virRlh6fAkh5-YSeHt4EIv-hFGneYk14d8DF51w"
  };

  const ephemeral_public_key_reader = {
    "kty":"EC",
    "use":"enc",
    "crv":"P-256",
    "x":"xVLtZaPPK-xvruh1fEClNVTR6RCZBsQai2-DrnyKkxg",
    "y":"-5-QtFqJqGwOjEL3Ut89nrE0MeaUp5RozksKHpBiyw0",
    "alg":"ECDH-ES",
    "kid":"P8p0virRlh6fAkh5-YSeHt4EIv-hFGneYk14d8DF51w"
  };

  const nonce = "Safdaer§$45_3342";
  const state = "34asfd34_34$34";
  const authz_request_parameters = {
    "aud":"https://self-issued.me/v2",
    "response_type":"vp_token",
    presentation_definition,
    "client_metadata":{
      "jwks":{
        "keys":[
          ephemeral_public_key_reader
        ]
      },
      "authorization_encrypted_response_alg":"ECDH-ES",
      "authorization_encrypted_response_enc":"A256GCM",
      "vp_formats":{
        "mso_mdoc":{
          "alg":[ "ES256", "ES384", "ES512", "EdDSA", "ESB256", "ESB320", "ESB384", "ESB512" ]
        }
      }
    },
    state,
    nonce,
    "client_id":"example.com ",
    "client_id_scheme":"x509_san_dns",
    "response_mode":"direct_post.jwt",
    "response_uri":"https://example.com/12345/response"
  };

  const authz_request_jwt_header = {
    "x5c":[
      "MIICPzCCAeWgAwIBAgIUDmBXx7+19KhwjltDbBW4BE0CRREwCgYIKoZIzj0EAwIwaTELMAkG A1UEBhMCVVQxDzANBgNVBAgMBlV0b3BpYTENMAsGA1UEBwwEQ2l0eTESMBAGA1UECgwJQUNNR SBDb3JwMRAwDgYDVQQLDAdJVCBEZXB0MRQwEgYDVQQDDAtleGFtcGxlLmNvbTAeFw0yMzEwMD MxNDQ5MzhaFw0yNDA5MjMxNDQ5MzhaMGkxCzAJBgNVBAYTAlVUMQ8wDQYDVQQIDAZVdG9waWE xDTALBgNVBAcMBENpdHkxEjAQBgNVBAoMCUFDTUUgQ29ycDEQMA4GA1UECwwHSVQgRGVwdDEU MBIGA1UEAwwLZXhhbXBsZS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARfLh+cWXq5f WRf9Cwo8VRkp9AAOOLaP3UCi3YY1VDHHEx7lAn9MCXo/vniqL88VFEi1PtT9ODaINVIXZFFjO rYo2swaTAdBgNVHQ4EFgQUxv6HtRQk9q7ASQCUqOqEun5S8QQwHwYDVR0jBBgwFoAUxv6HtRQ k9q7ASQCUqOqEun5S8QQwDwYDVR0TAQH/BAUwAwEB/zAWBgNVHREEDzANggtleGFtcGxlLmNv bTAKBggqhkjOPQQDAgNIADBFAiBt5/maixJyaWNKG8W9dAePhvhh5OHjswJaEjcyYiqoogIhA NwTGTdg12REzQMfQSXTSVtNp1jjJMPsipqR7kIK1JdT"
    ],
    "typ":"JWT",
    "alg":"ES256"
  };

  const static_private_key_reader_auth = {
    "kty":"EC",
    "kid":"Cv_aKIPqB8mkHqcJGUFq7zawf5vAyA6xv3PdJpJY1V8",
    "crv":"P-256",
    "x":"Xy4fnFl6uX1kX_QsKPFUZKfQADji2j91Aot2GNVQxxw",
    "y":"THuUCf0wJej--eKovzxUUSLU-1P04Nog1UhdkUWM6tg",
    "d":"5SOi-q3lIENTg-pyKeh3Vxhvu7IgYRm-IHPis2vfP8c"
  };

  const authz_request_object_jwt = await generate_authz_request_object_jwt(
    static_private_key_reader_auth, authz_request_jwt_header, authz_request_parameters);

  const presentation_submission = {
    "definition_id":"mDL-sample-req",
    "id":"mDL-sample-res",
    "descriptor_map":[
      {
        "id":"org.iso.18013.5.1.mDL",
        "format":"mso_mdoc",
        "path":"$"
      }
    ]
  };

  const vp_token = "o2d2ZXJzaW9uYzEuMGlkb2N1bWVudHOBo2dkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGxpc3N1ZXJTaWduZWSiam5hbWVTcGFjZXOhcW9yZy5pc28uMTgwMTMuNS4xi9gYWF-kaGRpZ2VzdElEGhU-n8JmcmFuZG9tUBhhBdaBj6yzbcAptxJFt5NxZWxlbWVudElkZW50aWZpZXJqYmlydGhfZGF0ZWxlbGVtZW50VmFsdWXZA-xqMTk5MC0wMS0wMdgYWF-kaGRpZ2VzdElEGgGfQ2JmcmFuZG9tUD_vjxEDDiHVNPYQrc-z3qJxZWxlbWVudElkZW50aWZpZXJvZG9jdW1lbnRfbnVtYmVybGVsZW1lbnRWYWx1ZWhBQkNEMTIzNNgYWPOkaGRpZ2VzdElEGhYhPvdmcmFuZG9tUPeQCdM61nPIh-T2KdDLzJ9xZWxlbWVudElkZW50aWZpZXJyZHJpdmluZ19wcml2aWxlZ2VzbGVsZW1lbnRWYWx1ZYKjamlzc3VlX2RhdGXZA-xqMjAyMC0wMS0wMWtleHBpcnlfZGF0ZdkD7GoyMDI1LTAxLTAxdXZlaGljbGVfY2F0ZWdvcnlfY29kZWFCo2ppc3N1ZV9kYXRl2QPsajIwMjAtMDEtMDFrZXhwaXJ5X2RhdGXZA-xqMjAyNS0wMS0wMXV2ZWhpY2xlX2NhdGVnb3J5X2NvZGViQkXYGFhgpGhkaWdlc3RJRBo23jMjZnJhbmRvbVBRkUqBtZ0-cdgL-Ah55BRHcWVsZW1lbnRJZGVudGlmaWVya2V4cGlyeV9kYXRlbGVsZW1lbnRWYWx1ZdkD7GoyMDI1LTAxLTAx2BhYWKRoZGlnZXN0SUQaZYFFSmZyYW5kb21QdKpwyVh1BG0egitavv8UWXFlbGVtZW50SWRlbnRpZmllcmtmYW1pbHlfbmFtZWxlbGVtZW50VmFsdWVlU21pdGjYGFhXpGhkaWdlc3RJRBoX9SvMZnJhbmRvbVBD8vu88PnK3lzRO9sRvnNDcWVsZW1lbnRJZGVudGlmaWVyamdpdmVuX25hbWVsZWxlbWVudFZhbHVlZUFsaWNl2BhYX6RoZGlnZXN0SUQaMaFJlmZyYW5kb21Q9AoSQ1BmYmKEqfADoeKDunFlbGVtZW50SWRlbnRpZmllcmppc3N1ZV9kYXRlbGVsZW1lbnRWYWx1ZdkD7GoyMDIwLTAxLTAx2BhYX6RoZGlnZXN0SUQaA8azMWZyYW5kb21Qb5Fu5qMeqndj9esMYWzh5XFlbGVtZW50SWRlbnRpZmllcnFpc3N1aW5nX2F1dGhvcml0eWxlbGVtZW50VmFsdWVmTlksVVNB2BhYWaRoZGlnZXN0SUQaUUgWkmZyYW5kb21Qgh02uXoPCuF2NCY9MlUucHFlbGVtZW50SWRlbnRpZmllcm9pc3N1aW5nX2NvdW50cnlsZWxlbWVudFZhbHVlYlVT2BhZCD-kaGRpZ2VzdElEGmTXNGdmcmFuZG9tUE2OWXxsntQn-CrtHF_AfwVxZWxlbWVudElkZW50aWZpZXJocG9ydHJhaXRsZWxlbWVudFZhbHVlWQft_9j_4AAQSkZJRgABAQAAAAAAAAD_4gIoSUNDX1BST0ZJTEUAAQEAAAIYAAAAAAQwAABtbnRyUkdCIFhZWiAAAAAAAAAAAAAAAABhY3NwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAA9tYAAQAAAADTLQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAlkZXNjAAAA8AAAAHRyWFlaAAABZAAAABRnWFlaAAABeAAAABRiWFlaAAABjAAAABRyVFJDAAABoAAAAChnVFJDAAABoAAAAChiVFJDAAABoAAAACh3dHB0AAAByAAAABRjcHJ0AAAB3AAAADxtbHVjAAAAAAAAAAEAAAAMZW5VUwAAAFgAAAAcAHMAUgBHAEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFhZWiAAAAAAAABvogAAOPUAAAOQWFlaIAAAAAAAAGKZAAC3hQAAGNpYWVogAAAAAAAAJKAAAA-EAAC2z3BhcmEAAAAAAAQAAAACZmYAAPKnAAANWQAAE9AAAApbAAAAAAAAAABYWVogAAAAAAAA9tYAAQAAAADTLW1sdWMAAAAAAAAAAQAAAAxlblVTAAAAIAAAABwARwBvAG8AZwBsAGUAIABJAG4AYwAuACAAMgAwADEANv_bAEMAEAsMDgwKEA4NDhIREBMYKBoYFhYYMSMlHSg6Mz08OTM4N0BIXE5ARFdFNzhQbVFXX2JnaGc-TXF5cGR4XGVnY__bAEMBERISGBUYLxoaL2NCOEJjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY__AABEIALAAeQMBIgACEQEDEQH_xAAaAAADAQEBAQAAAAAAAAAAAAAAAwQFBgcB_8QALhAAAgIBAwIEBQMFAAAAAAAAAAMEEyMFFDNDUyRjc4MBBhU0oxZEkyU1UVWz_8QAFgEBAQEAAAAAAAAAAAAAAAAAAAME_8QAFhEBAQEAAAAAAAAAAAAAAAAAAAMT_9oADAMBAAIRAxEAPwDlwACSRoAAAAW1CrQGgS7pR93q_wDAFIEu6C0CoAAAAAAAAAFDRQ0AFNGksoBVtrRTQAqqAUFQAN9VoWh6oW-UA1TRvSJbQbykheptoCopUEigAAAAAAFSmq4gktqUSxVWtAbFgNlNOji_LihsBVRsqDVkxm_LiukQfpyUdkNCuTklfK-LK0y5WjNitqaegks9VqqgZODlaW2Ll6QrpG9PVa2pXS5TLnq2srymhJBxFRK1RUriCQAACQAAAglcpfpaiCVympACsnRxVGoogil6g1GjQAkC2ogqbP8AKUX1Daiog2ClKqUo5zVIFVp2Rl6pFtUBwbcQKGz_ALpoqLyhlNAACQAAAllcpfFbUQSuUaFZOoiz1VF6p6u6ckpqhtVqrVBXR2SpQ23KcbAa1rVKOtqtihVVaNtOXlNlKxWios9tuWUB1pK3KSqa1vV9oqy9UDz7VMUpqhUXiKte_ukr1RSsSgy1AAASAChoCmqL1RbVClelaakVVTagrJLFgeUbKqlRaqhtQqVxBqZass9SlNqOoqaqL9-33VHL6Mrx9p2XKqoCDaqbF81uUg-lqt6vpGzAVVFUoaBlxYFTcXEXtt5VKyjahTW1NVUB59PU36o23ujRs_K22olDLUAKAJFDRQ0Bqi-LKqaQDVBWTe3TcWK0lntaNi8QqVFtDUboLVW1HRnJRYErdYjqNq1qlZcoBbU1o1spSuVtXqjasQVEgq23iyg1XLbytKiCfPVAytbiKjktZbbqjf4iAbKlKbKa3utFBgKAAAUNFAA0aKADeit8KNVKtMuA3ul9SmhqbOl1Wl_dOXixVW27pqjZVU391b7oVag3lJVKq4mjbSQGnJfNsrxSldo6OVKqU1rekcHKlbqU2U3qlUqlCgAqygPdAUAAABU0GtFNbUErFiAqi8RswMpgwOIvU2okq62LAVUNVpaldUggT1VZTUVKV3QqbUDQ3XaBSiQy9exaW1rTiG8uI7L5jlKa3a9rK05dtTeWpRVKqACrYYrVNVUKapqiqRQAASXyorVKxKIKi_3be6StVb9r0gqlVyqKmqa1ouL8Pj8Pjj-GVnGbsWKptrWt4lAZcA2dgQKgNixVN7p2UVXhVElWDF0trTZi6MpRepVQ20KhSlKINU1RUBXmip-s7XErlOXlSmz222gakC1Wlyp_VbiMvWVKVFV0ml8ptUCLF7SvymNryqpSovaUEilKtxWim7qBibaoa1VSjU1SA1XErF_yKpMZSlNVlKtr5opTVKblVxF-6i_6v8oCmxdhFU3lt5SVsVsXpNOolRbZSoHutMaU1u6a3KBjZVZTeVPV9LUpTfFN5RWsRlJ0uL3eUlbF2qospXE0DZVlgbXqqOogfaqOD0ue3f5fyneK4sRJqkGmXPlYsRqN4jnJ8rqtJDLlBAV_V2yv2o1VvVVla3ENbK8BUr-JpVI1VUrVMrcSsrfVMGU23VGt801GxZWl6Nl6pgxVNa3EVSXymq3SsuI3lSlSlYuXzTkpSmqlVHRq0tu1U0DLn2qnhaGsKlVKa1Rlkh__2dgYWGGkaGRpZ2VzdElEGnHvWL5mcmFuZG9tUPHruXHjv35Iu-rzOkKBD2xxZWxlbWVudElkZW50aWZpZXJ2dW5fZGlzdGluZ3Vpc2hpbmdfc2lnbmxlbGVtZW50VmFsdWVjVVNBamlzc3VlckF1dGiEQ6EBJqEYIVkCvjCCArowggJhoAMCAQICFA7VlOKXxKg_rJ6UiVqmXVQjpptXMAoGCCqGSM49BAMCMGAxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJOWTEZMBcGA1UECgwQSVNPbURMIFRlc3QgUm9vdDEpMCcGA1UEAwwgSVNPMTgwMTMtNSBUZXN0IENlcnRpZmljYXRlIFJvb3QwHhcNMjMxMTE0MTAwMTA1WhcNMjQxMTEzMTAwMTA1WjBrMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTlkxIjAgBgNVBAoMGUlTT21ETCBUZXN0IElzc3VlciBTaWduZXIxKzApBgNVBAMMIklTTzE4MDEzLTUgVGVzdCBDZXJ0aWZpY2F0ZSBTaWduZXIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQgaK6KmQ1mWKt-Vo6ixfHxsmX9YlGAuUPkOvQ_uHrxgsZLC6FheRwtU3v-5GGkHD70FJNmz7DJUiR6G8TWMYZGo4HtMIHqMB0GA1UdDgQWBBQEpN0hSF6BFZJCDvZwASaa6ewoXzAfBgNVHSMEGDAWgBQ1RoOxz04dQvKPF76VhBf-jMv3EDAxBglghkgBhvhCAQ0EJBYiSVNPMTgwMTMtNSBUZXN0IFNpZ25lciBDZXJ0aWZpY2F0ZTAOBgNVHQ8BAf8EBAMCB4AwFQYDVR0lAQH_BAswCQYHKIGMXQUBAjAdBgNVHRIEFjAUgRJleGFtcGxlQGlzb21kbC5jb20wLwYDVR0fBCgwJjAkoCKgIIYeaHR0cHM6Ly9leGFtcGxlLmNvbS9JU09tREwuY3JsMAoGCCqGSM49BAMCA0cAMEQCIGV5CQ0EFGjFzVBSqWfaPVUMziescVQ4W-lxw5bq7nCBAiBf1D9SPeA05Sdf0iWHanW3N0FBtS7Iz5XdSKWT2IqMKFkFzNgYWQXHpmd2ZXJzaW9uYzEuMG9kaWdlc3RBbGdvcml0aG1nU0hBLTI1Nmx2YWx1ZURpZ2VzdHOhcW9yZy5pc28uMTgwMTMuNS4xuB4aAZ9DYlggxtL2LRFm_GWjYft8lw02WZS4CLbChc-NakfbNNyTuAcaA8azMVggpZCl5WRduZFAMb0vykZCxA-AdeM1R8eoiC1d9d3pkLUaEU3f71ggHp0cG-ZNraR6vcOgLZSORP9rDEipOlXzHh18YamiANoaFT6fwlggEphIDgQUoblEdUCq34aMJ50OQ8QmCVFJuQgiB1_YwhoaFiE-91ggeEtCLmPzCOD0suxhDwW43s7yNc1x6Jd4DZ6tO4ObD6IaFxmGZVgguLSRAKQ1dwJGOS_soukGSZUkCqvW7zN4R4eoTO-phFAaF_UrzFggJ4LaSDWgaeLF8hkPWLaDZGrjYCOuLYCcZk5tWXug4aMaGthQz1ggg3jAWBkkHRE9l4AoDdqdFYgJ56crlzeAf47JtJ662VMaKXLy5lggQBw9uLpXYKFP4ZdoO7zzb_vtymKttmA_qeaaEW_jbWUaLBiyUVggR3AnIGXnmMTMHPjuR19-e4lLs6vi3digyHN0iyzc3PkaMQCGYVggKvs-nJVYFRwH_TbFGPy1X_t69MR1l94toRIIK98UBvAaMaFJllggCoQYDBIY_rk6s0MhMbC8ibfzGegfY-Pfwauy9GHW_38aMqbHz1ggtrjS6GQsMtSQaKf7Voa6kxPLDqK24EZ-9WhB8JaO4f4aNUVesFggOzxV3ZrJ8FQMCuThmR6L7B4SMN5bxLy05i6v9wgpejYaNt4zI1ggzzpJiJuTxtgMDAxycYe7TYmsovh5Aw_EDfDX8rRqYV4aOTYKk1ggEnnTJHhcMseTjVtPRGnCRRCE0WvwelO1dECZvlLXeIQaSkPcgFggyKs6jeFkCIjai1k5xYqZyqjK45ImuVOzPVC8jPXPXksaT9EOg1ggO9johmBdbxTYTcMQDSB1K9jwdd350VIjMuCHDZ8DDUEaUUgWklggGz_ddBP3N_0mxg7fco-oJ2HorIFAptTj78ZseE5gfmAaUUqijlgglmqfTA5d9Wi85wDcpdTO1NrlH02nOx4zP7FZ8TE7KroaXagLOFggt3m7aHSfgJ3rEl1nn-Pp8YitK572a64L2GAa-UZCiGkaXyMT31gghLUPLnlPsZaDTk7Yd_JsjeEuWwIeAyu5FNeYRDkajlUaYLUtAlggb0He6jVXV1OGqzZidHIWpba3yCffluLpOiKAiVzVeXEaZNc0Z1gggSJJmw3Dt0YsH38Flq1hxybrP4tWRR6nSUUPZOah6BUaZYFFSlgg9-83mx19kFY-tbUDXndIdXL1oXs_2nYgchpnvWuENjIaaMXpU1gg5iCCWrzVNvXZa8I_jfmTpwZFxdmEfv7D3rcYhza65Dcaa4ST6Vggrz6sluAmWjOaVRmKC6lLFyqEglIyTwZlGA3Q6tbF_WcacYeIV1ggk1fOHKjmMaPlh7SaVtWk-6jC38DqPcWz3UcH6xuiZ1Mace9YvlggJCOAb023GTSEcNt48NYF2ZOM2p9RIqO8W91zORSzMFQaecXSi1ggFZp2VG3VaCEgchdZPgbK8JSuYsMCmy9Dy4WXyZD1Z1RtZGV2aWNlS2V5SW5mb6FpZGV2aWNlS2V5pAECIAEhWCCS9P-a8TB2KJzTBif0C32CrhjX3XKMVykLFFTHdFXpnSJYIADctY3zP9kjfSptLs9kyUhDUDRf4xOSIs0FkbyjHnsFZ2RvY1R5cGV1b3JnLmlzby4xODAxMy41LjEubURMbHZhbGlkaXR5SW5mb6Nmc2lnbmVkwHQyMDIzLTExLTE2VDA5OjI1OjIyWml2YWxpZEZyb23AdDIwMjMtMTEtMTZUMDk6MjU6MjJaanZhbGlkVW50aWzAdDIwMjMtMTItMTZUMDk6MjU6MjJaWEC8OJJedu29mak8hVi1X__VJhpQ6QhgOhTqHZMtdrqyWdalv457ykvXnq3U5Zl5NC1GDyIDdr23_L67HUOKFqCHbGRldmljZVNpZ25lZKJqbmFtZVNwYWNlc9gYQaBqZGV2aWNlQXV0aKFvZGV2aWNlU2lnbmF0dXJlhEOhASag9lhAX4O7CImR03EijrZDHYgdzQefwdix5l-hJ7ow05OvOyQj0f_kW9GYbvWbDYbHN_kreXHaXpDh5Swm1nc5X39N6mZzdGF0dXMA";

  const authz_response_parameters = {
    presentation_submission,
    vp_token
  };

  const mdoc_generated_nonce = "23452§§%§$2_KefO";
  const authz_response_object_jwt = await generate_authz_response_object_jwt(
    authz_response_parameters, mdoc_generated_nonce, nonce, ephemeral_public_key_reader);

  const authz_response_jwt_header = JSON.parse(base64url.decode(authz_response_object_jwt.split('.')[0]));

  const ephemeral_private_key_mdoc = {
     // TBD: needs to be read from memory via debugger
  };

  const ephemeral_public_key_mdoc = authz_response_jwt_header.epk;

  // -------
  // OID4VPHandover and SessionTranscriopt using the following params:
  // mdoc_generated_nonce = "23452§§%§$2_KefO"
  // client_id = "example.com".
  // response_uri = "https://example.com/12345/response"
  // nonce = "Safdaer§$45_3342"
  const oid4vp_handover_hex = "8398201827186718ea18a7184618bf182418d5189d00186b1841184418f618ff18851825183d14182d08186b18e91882183f182a183518ba18da187a18ef18fd9820187911184e183c186d18b518a4183e1893186618aa18bb02184518b11844131845184c18ff0b185a189618570a0d188e182318b71841182618e57153616664616572c2a72434355f33333432";
  const session_transcript_hex = "83f6f68398201827186718ea18a7184618bf182418d5189d00186b1841184418f618ff18851825183d14182d08186b18e91882183f182a183518ba18da187a18ef18fd9820187911184e183c186d18b518a4183e1893186618aa18bb02184518b11844131845184c18ff0b185a189618570a0d188e182318b71841182618e57153616664616572c2a72434355f33333432";
  // -------

  console.log("----------------");
  console.log("Annex B Examples");
  console.log("----------------");

  console.log("-------------------------------");
  console.log("Example: Static Wallet Metadata");
  console.log("-------------------------------");
  console.log(JSON.stringify(static_wallet_metadata, null, 2));

  console.log("--------------------------------");
  console.log("Example: Presentation Definition");
  console.log("--------------------------------");
  console.log(JSON.stringify(presentation_definition, null, 2));

  console.log("-----------------------------------------");
  console.log("Example: Ephemeral Private Reader Key JWK");
  console.log("-----------------------------------------");
  console.log(JSON.stringify(ephemeral_private_key_reader, null, 2));

  console.log("-----------------------------------------");
  console.log("Example: Ephemeral Public Reader Key JWK");
  console.log("-----------------------------------------");
  console.log(JSON.stringify(ephemeral_public_key_reader, null, 2));

  console.log("------------------------------------------------");
  console.log("Example: Authorization Request Object parameters");
  console.log("------------------------------------------------");
  console.log(JSON.stringify(authz_request_parameters, null, 2));

  console.log("------------------------------------------------------");
  console.log("Example: Authorization Request Object JWT (JAR) Header");
  console.log("------------------------------------------------------");
  console.log(JSON.stringify(authz_request_jwt_header, null, 2));

  console.log("------------------------------------------------------------------------");
  console.log("Example: Static Private Reader Key JWK corresponding to 'x5c' JWT Header");
  console.log("------------------------------------------------------------------------");
  console.log(JSON.stringify(static_private_key_reader_auth, null, 2));

  console.log("----------------------------------------------------------");
  console.log("Example: Authorization Request Object encoded as JWT (JAR)");
  console.log("----------------------------------------------------------");
  console.log(authz_request_object_jwt);

  console.log("--------------------------------");
  console.log("Example: Presentation Submission");
  console.log("--------------------------------");
  console.log(JSON.stringify(presentation_submission, null, 2));

  console.log("-----------------");
  console.log("Example: VP Token");
  console.log("-----------------");
  console.log(vp_token);

  console.log("-------------------------------------------------");
  console.log("Example: Authorization Response Object parameters");
  console.log("-------------------------------------------------");
  console.log(JSON.stringify(authz_response_parameters, null, 2));

  console.log("-----------------------------------------------------------");
  console.log("Example: Authorization Response Object encoded as JWT (JARM)");
  console.log("-----------------------------------------------------------");
  console.log(authz_response_object_jwt);

  console.log("--------------------------------------------------------");
  console.log("Example: Authorization Response Object JWT (JARM) Header");
  console.log("--------------------------------------------------------");
  console.log(JSON.stringify(authz_response_jwt_header, null, 2));

  console.log("--------------------------------------");
  console.log("Example: Ephemeral Public MDOC Key JWK");
  console.log("--------------------------------------");
  console.log(JSON.stringify(ephemeral_public_key_mdoc, null, 2));

  console.log("--------------------------------------");
  console.log("Example: Ephemeral Private MDOC Key JWK");
  console.log("--------------------------------------");
  console.log("In node-jose:encrypt.js: line 196: print the following expresssion: JSON.stringify(epk.toJSON(true, [\"kid\"]), null, 2) ");

  console.log("-----------------------------------------------------------");
  console.log("Example: OID4VPHandover CBOR Hex");
  console.log("-----------------------------------------------------------");
  console.log(oid4vp_handover_hex);

  console.log("-----------------------------------------------------------");
  console.log("Example: SessionTranscipt CBOR Hex");
  console.log("-----------------------------------------------------------");
  console.log(session_transcript_hex);
}

async function generate_authz_request_object_jwt(static_private_key_reader_auth, authz_request_jwt_header, authz_request_parameters) {
  const key = await jose.JWK.asKey(static_private_key_reader_auth);    
  const jwt = await jose.JWS.createSign({ format: 'compact', fields: authz_request_jwt_header }, key).
          update(JSON.stringify(authz_request_parameters)).
          final();
  return jwt;
}

async function generate_authz_response_object_jwt(
  authz_response_parameters, mdoc_generated_nonce, nonce, ephemeral_public_key_reader) {

  const encKey = await jose.JWK.asKey(ephemeral_public_key_reader);
  const apu = base64url(mdoc_generated_nonce);
  const apv = base64url(nonce);

  const jwe = await jose.JWE.createEncrypt({
      format: 'compact',
      fields: {
        alg: 'ECDH-ES',
        enc: 'A256GCM',
        apu: apu,
        apv: apv,
        kid: ephemeral_public_key_reader.kid
      },
  }, {
      key: encKey,
  }).update(JSON.stringify(authz_response_parameters)).final();

  try {
    fs.writeFileSync('encrypted.txt', jwe);
    // file written successfully
  } catch (err) {
    console.error(err);
  }

  return jwe;
}

// async function decrypt_authz_response_jwt_headers(authz_response_object_jwt, ephemeral_private_key_reader) {
//   const decKey = await jose.JWK.asKey(ephemeral_private_key_reader);
//   const decrypted = await jose.JWE.createDecrypt(decKey).decrypt(authz_response_object_jwt);
//   console.log('decrypted: ', JSON.parse(decrypted.payload.toString('utf8')));
// }

// async function extract() {
//   const args = process.argv.slice(2);

//   const key = fs.readFileSync(args[0]);
//   const keystore = jose.JWK.createKeyStore();

//   var DUMP_PRIVATE_KEY = ('true' == args[1]);

//   keystore
//     .add(key, 'pem')
//     .then(function(_) {
//       const jwks = keystore.toJSON(DUMP_PRIVATE_KEY);
//       console.log(JSON.stringify(jwks, null, 4));
//     });
// }

main()
