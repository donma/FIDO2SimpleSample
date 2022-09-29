using Fido2NetLib;
using Fido2NetLib.Development;
using Fido2NetLib.Objects;
using Fido2SimpleSample.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System.Text;
using System.Text.Json.Serialization;
using static Fido2NetLib.Fido2;

namespace Fido2SimpleSample
{
    [Route("api/auth")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private IFido2 _fido2;


        public AuthController(IFido2 fido2)
        {
            _fido2 = fido2;
        }

        [HttpGet]

        public string Get()
        {
            return "Backend Service";


        }




        [HttpPost]
        [Route("registuser")]
        [Produces("application/json")]

        public IActionResult RegistUser([FromForm] string userid,
                                             [FromForm] string displayName,
                                             [FromForm] string userpass)
        {
            try
            {

                if (string.IsNullOrEmpty(userid))
                {

                    return Ok(new CredentialCreateOptions { Status = "error", ErrorMessage = "userid cannot be null" });
                }


                var user = AuthStorageUtil.GetUserById(userid);
                if (user == null)
                {

                    user = new DFido2User
                    {
                        DisplayName = displayName,
                        Name = userid,
                        Id = Encoding.UTF8.GetBytes(userid),
                        Pass = AuthStorageUtil.GetMD5(System.Text.Encoding.UTF8.GetBytes(userpass))
                    };

                    AuthStorageUtil.SaveUserData(user);
                    return Ok(new CredentialCreateOptions { Status = "ok" });
                }
                else
                {

                    return Ok(new CredentialCreateOptions { Status = "error", ErrorMessage = "regist already." });
                }




            }
            catch (Exception e)
            {
                return Ok(new CredentialCreateOptions { Status = "error", ErrorMessage = e.Message });

            }
        }






        [HttpPost]
        [Route("makeCredentialOptions")]
        [Produces("application/json")]

        public IActionResult MakeCredentialOptions([FromForm] string userid,
                                             [FromForm] string userpass,
                                             [FromForm] string attType,
                                             [FromForm] string authType,
                                             [FromForm] bool requireResidentKey,
                                             [FromForm] string userVerification)
        {
            try
            {

                if (string.IsNullOrEmpty(userid))
                {
                    return Ok(new CredentialCreateOptions { Status = "error", ErrorMessage = "user id null." });

                }
                if (string.IsNullOrEmpty(userpass))
                {
                    return Ok(new CredentialCreateOptions { Status = "error", ErrorMessage = "userpass null." });

                }




                // 1. Get user from DB by username

                var user = AuthStorageUtil.GetUserById(userid);
                if (user == null)
                {

                    return Ok(new CredentialCreateOptions { Status = "error", ErrorMessage = "User Not Existed." });


                }

                if (AuthStorageUtil.GetMD5(System.Text.Encoding.UTF8.GetBytes(userpass)) != user.Pass)
                {
                    return Ok(new CredentialCreateOptions { Status = "error", ErrorMessage = "User Data Error." });

                }



                // 2. Get user existing keys by username
                //var existingKeys = DemoStorage.GetCredentialsByUser(user).Select(c => c.Descriptor).ToList();

                var existingKeys = AuthStorageUtil.GetCredentialsByUser(user.Name).Select(e => e.Descriptor).ToList(); ;


                // 3. Create options
                var authenticatorSelection = new AuthenticatorSelection
                {
                    RequireResidentKey = requireResidentKey,
                    UserVerification = userVerification.ToEnum<UserVerificationRequirement>()
                };

                if (!string.IsNullOrEmpty(authType))
                    authenticatorSelection.AuthenticatorAttachment = authType.ToEnum<AuthenticatorAttachment>();

                var exts = new AuthenticationExtensionsClientInputs()
                {
                    Extensions = true,
                    UserVerificationMethod = true,
                };

                var options = _fido2.RequestNewCredential(user, existingKeys, authenticatorSelection, attType.ToEnum<AttestationConveyancePreference>(), exts);



                // 4. Temporarily store options, session/in-memory cache/redis/db
                HttpContext.Session.SetString("fido2.attestationOptions", options.ToJson());

                // 5. return options to client
                return Ok(options);
            }
            catch (Exception e)
            {
                return Ok(new CredentialCreateOptions { Status = "error", ErrorMessage = e.Message });
                //   return Problem();
            }
        }




        [HttpPost]
        [Route("makeCredential")]
        [Produces("application/json")]
        public async Task<IActionResult> MakeCredential([FromBody] AuthenticatorAttestationRawResponse attestationResponse, CancellationToken cancellationToken)
        {
            try
            {
                // 1. get the options we sent the client
                var jsonOptions = HttpContext.Session.GetString("fido2.attestationOptions");
                var options = CredentialCreateOptions.FromJson(jsonOptions);

                // 2. Create callback so that lib can verify credential id is unique to this user
                //if (AuthStorageUtil.IsCredentialIdExisted(attestationResponse.Id)) {
                //    return Ok(new CredentialMakeResult(status: "error", errorMessage:"Credentail Existed", result: null));
                //}

                IsCredentialIdUniqueToUserAsyncDelegate callback = static async (args, cancellationToken) =>
                {
                    //    var users = await DemoStorage.GetUsersByCredentialIdAsync(args.CredentialId, cancellationToken);
                    if (AuthStorageUtil.IsCredentialIdExisted(args.CredentialId))
                        return false;

                    return true;
                };




                // 2. Verify and make the credentials
                var success = await _fido2.MakeNewCredentialAsync(attestationResponse, options, callback, cancellationToken: cancellationToken);


                // 3. Store the credentials in db





                var storeCredentail = new StoredCredential
                {
                    Descriptor = new PublicKeyCredentialDescriptor(success.Result.CredentialId),
                    PublicKey = success.Result.PublicKey,
                    UserHandle = success.Result.User.Id,
                    SignatureCounter = success.Result.Counter,
                    CredType = success.Result.CredType,
                    RegDate = DateTime.Now,
                    AaGuid = success.Result.Aaguid
                };


                AuthStorageUtil.SaveStoredCredential(success.Result.User.Name, storeCredentail);

                // 4. return "ok" to the client
                return Ok(success);

            }
            catch (Exception e)
            {
                return Ok(new CredentialMakeResult(status: "error", errorMessage: FormatException(e), result: null));
            }
        }

        private string FormatException(Exception e)
        {
            return string.Format("{0}{1}", e.Message, e.InnerException != null ? " (" + e.InnerException.Message + ")" : "");
        }




        [HttpPost]
        [Route("assertionOptions")]
        [Produces("application/json")]
        public ActionResult AssertionOptionsPost([FromForm] string userid, [FromForm] string userpass, [FromForm] string userVerification)
        {
            try
            {
                var existingCredentials = new List<PublicKeyCredentialDescriptor>();

                if (!string.IsNullOrEmpty(userid))
                {
                    // 1. Get user from DB
                    var user = AuthStorageUtil.GetUserById(userid) ?? throw new ArgumentException("user was not registered");


                    if (AuthStorageUtil.GetMD5(System.Text.Encoding.UTF8.GetBytes(userpass)) != user.Pass) {
                        throw new ArgumentException("user data error");
                    }


                    // 2. Get registered credentials from database
                    existingCredentials = AuthStorageUtil.GetCredentialsByUser(userid).Select(c => c.Descriptor).ToList();
                }

                var exts = new AuthenticationExtensionsClientInputs()
                {
                    UserVerificationMethod = true
                };

                // 3. Create options
                var uv = string.IsNullOrEmpty(userVerification) ? UserVerificationRequirement.Discouraged : userVerification.ToEnum<UserVerificationRequirement>();
                var options = _fido2.GetAssertionOptions(
                    existingCredentials,
                    uv,
                    exts
                );

                // 4. Temporarily store options, session/in-memory cache/redis/db
                HttpContext.Session.SetString("fido2.assertionOptions", options.ToJson());
                
                // 5. Return options to client
                // return Json(options);

                return Ok(options);
            }

            catch (Exception e)
            {
                return Ok(new CredentialCreateOptions { Status = "error", ErrorMessage = e.Message });
                // return Json(new AssertionOptions { Status = "error", ErrorMessage = FormatException(e) });
            }

        }

        [HttpPost]
        [Route("makeAssertion")]
        [Produces("application/json")]
        public async Task<IActionResult> MakeAssertion([FromBody] AuthenticatorAssertionRawResponse clientResponse, CancellationToken cancellationToken)
        {
            try
            {
                // 1. Get the assertion options we sent the client
                var jsonOptions = HttpContext.Session.GetString("fido2.assertionOptions");
                var options = AssertionOptions.FromJson(jsonOptions);

                // 2. Get registered credential from database

                //var creds = AuthStorageUtil.GetStoreCredentialByUserId(, clientResponse.Id) ?? throw new Exception("Unknown credentials");

                var userId= AuthStorageUtil.GetUserIdByCredentialsById(clientResponse.Id);

                if (userId == null) {
                    throw new Exception("Unknown credentials");
                }
                var creds = AuthStorageUtil.GetStoreCredentialByUserId(userId, clientResponse.Id);



                if (creds == null) {
                    throw new Exception("Unknown credentials");
                }



                // 3. Get credential counter from database
                var storedCounter = creds.SignatureCounter;

                // 4. Create callback to check if userhandle owns the credentialId
                //IsUserHandleOwnerOfCredentialIdAsync callback = static async (args, cancellationToken) =>
                //{

                    
                //    var storedCreds = await DemoStorage.GetCredentialsByUserHandleAsync(args.UserHandle, cancellationToken);
                //    return storedCreds.Exists(c => c.Descriptor.Id.SequenceEqual(args.CredentialId));
                //    return true;
                //};

                // 5. Make the assertion
                var res = await _fido2.MakeAssertionAsync(clientResponse, options, creds.PublicKey, storedCounter, null, cancellationToken: cancellationToken);

                // 6. Store the updated counter
                // DemoStorage.UpdateCounter(res.CredentialId, res.Counter);

                // 7. return OK to client
                return Ok(res);
            }
            catch (Exception e)
            {
                //return Json(new AssertionVerificationResult { Status = "error", ErrorMessage = FormatException(e) });
                return Ok(new AssertionVerificationResult { Status = "error", ErrorMessage = FormatException(e) });
            }
        }


    }
}
