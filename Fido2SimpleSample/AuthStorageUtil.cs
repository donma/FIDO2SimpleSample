using Fido2NetLib;
using Fido2NetLib.Development;
using Fido2SimpleSample.Models;
using Newtonsoft.Json;
using System.Text.Json.Serialization;

namespace Fido2SimpleSample
{
    public static class AuthStorageUtil
    {

        private static string StoragePath { get; set; }
        private static string UserStoragePath { get; set; }

        private static string CredentailPath { get; set; }

        private static string LogPath { get; set; }
        static AuthStorageUtil()
        {
            StoragePath = AppDomain.CurrentDomain.BaseDirectory + "TEMP_STORAGE" + Path.DirectorySeparatorChar;
            UserStoragePath = AppDomain.CurrentDomain.BaseDirectory + "TEMP_STORAGE" + Path.DirectorySeparatorChar + "USER" + Path.DirectorySeparatorChar;
            CredentailPath = AppDomain.CurrentDomain.BaseDirectory + "TEMP_STORAGE" + Path.DirectorySeparatorChar + "CREDENTAIL" + Path.DirectorySeparatorChar;
            LogPath = AppDomain.CurrentDomain.BaseDirectory + "TEMP_STORAGE" + Path.DirectorySeparatorChar + "LOG" + Path.DirectorySeparatorChar;



            Directory.CreateDirectory(StoragePath);
            Directory.CreateDirectory(UserStoragePath);
            Directory.CreateDirectory(CredentailPath);
            Directory.CreateDirectory(LogPath);
        }

        public static void WriteLog(string id, string content) {

            File.WriteAllText(LogPath + id, content);
        
        }

        public static DFido2User? GetUserById(string userId)
        {
            if (!File.Exists(UserStoragePath + userId))
            {
                return null;
            }

            var str = File.ReadAllText(UserStoragePath + userId);
            return JsonConvert.DeserializeObject<DFido2User>(str);

        }

        public static void SaveUserData(DFido2User user)
        {

            File.WriteAllText(UserStoragePath + user.Name, JsonConvert.SerializeObject(user));

        }

        public static  bool IsCredentialIdExisted(byte[] credentialId)
        {
            return File.Exists(CredentailPath + GetMD5(credentialId));
        }

        public static string GetMD5(byte[] input)
        {
            // Use input string to calculate MD5 hash
            using (System.Security.Cryptography.MD5 md5 = System.Security.Cryptography.MD5.Create())
            {
            
                byte[] hashBytes = md5.ComputeHash(input);

                return Convert.ToHexString(hashBytes); // .NET 5 +

            }
        }

        public static void SaveStoredCredential(string userId, StoredCredential sc) {


            Directory.CreateDirectory(StoragePath + userId + "_" + "CREDS");

            System.IO.File.WriteAllText(StoragePath + userId + "_" + "CREDS"+Path.DirectorySeparatorChar+ GetMD5(sc.Descriptor.Id), JsonConvert.SerializeObject(sc));

            System.IO.File.WriteAllText(CredentailPath + GetMD5(sc.Descriptor.Id), userId);


        }

        public static List<StoredCredential> GetCredentialsByUser(string userId) {

            if (!Directory.Exists(StoragePath + userId + "_" + "CREDS")) {
                return new List<StoredCredential>();
            
            }


            var res = new List<StoredCredential>();

            var  files = Directory.GetFiles(StoragePath + userId + "_" + "CREDS");

            if (files != null) {

                foreach (var f in files) {
                   
                    res.Add(JsonConvert.DeserializeObject<StoredCredential>(File.ReadAllText(f)));
                }
            
            }

            return res;
        }


        public static string? GetUserIdByCredentialsById(byte[] credentialsById)
        {

            if (!File.Exists(CredentailPath + GetMD5(credentialsById))) {
                return null;
            }

            return System.IO.File.ReadAllText(CredentailPath + GetMD5(credentialsById));
        }

        public static StoredCredential? GetStoreCredentialByUserId(string userId, byte[] storeCredentailId) {

            if (!Directory.Exists(StoragePath + userId + "_" + "CREDS"))
            {
                return null;
            }

            if (!File.Exists(StoragePath + userId + "_" + "CREDS" + Path.DirectorySeparatorChar + GetMD5(storeCredentailId))) {
                return null;
            }

            return JsonConvert.DeserializeObject<StoredCredential>(File.ReadAllText(StoragePath + userId + "_" + "CREDS" + Path.DirectorySeparatorChar + GetMD5(storeCredentailId)));
        }
    }
}
