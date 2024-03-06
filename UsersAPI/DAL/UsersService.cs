using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using UsersAPI.Authentication;
using UsersAPI.DAO;
using UsersAPI.Exceptions;

namespace UsersAPI.DAL
{
    internal class UsersService : IUsersService
    {
        private readonly SqlConnection sqlConn;
        private readonly string encryptionKey;
        private readonly IJwtAuthentication jwtAuthtentication;

        public UsersService(IConfiguration configuration, IJwtAuthentication auth)
        {
            this.sqlConn = new SqlConnection(configuration["ConnectionStrings:ConnStr"]);
            this.encryptionKey = configuration["Encryption:Secret"];
            this.jwtAuthtentication = auth;
        }

        public static string Encrypt(string plainText, string passPhrase)
        {
            // Salt and IV is randomly generated each time, but is preprended to encrypted cipher text
            // so that the same Salt and IV values can be used when decrypting.  
            var saltStringBytes = Generate128BitsOfRandomEntropy();
            var ivStringBytes = Generate128BitsOfRandomEntropy();
            var plainTextBytes = Encoding.UTF8.GetBytes(plainText);
            using (var password = new Rfc2898DeriveBytes(passPhrase, saltStringBytes, 1000))
            {
                var keyBytes = password.GetBytes(16);
                using (var symmetricKey = new RijndaelManaged())
                {
                    symmetricKey.BlockSize = 128;
                    symmetricKey.Mode = CipherMode.CBC;
                    symmetricKey.Padding = PaddingMode.PKCS7;
                    using (var encryptor = symmetricKey.CreateEncryptor(keyBytes, ivStringBytes))
                    {
                        using (var memoryStream = new MemoryStream())
                        {
                            using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                            {
                                cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
                                cryptoStream.FlushFinalBlock();
                                // Create the final bytes as a concatenation of the random salt bytes, the random iv bytes and the cipher bytes.
                                var cipherTextBytes = saltStringBytes;
                                cipherTextBytes = cipherTextBytes.Concat(ivStringBytes).ToArray();
                                cipherTextBytes = cipherTextBytes.Concat(memoryStream.ToArray()).ToArray();
                                memoryStream.Close();
                                cryptoStream.Close();
                                return Convert.ToBase64String(cipherTextBytes);
                            }
                        }
                    }
                }
            }
        }

        public static string Decrypt(string cipherText, string passPhrase)
        {
            // Get the complete stream of bytes that represent:
            // [32 bytes of Salt] + [32 bytes of IV] + [n bytes of CipherText]
            var cipherTextBytesWithSaltAndIv = Convert.FromBase64String(cipherText);
            // Get the saltbytes by extracting the first 32 bytes from the supplied cipherText bytes.
            var saltStringBytes = cipherTextBytesWithSaltAndIv.Take(16).ToArray();
            // Get the IV bytes by extracting the next 32 bytes from the supplied cipherText bytes.
            var ivStringBytes = cipherTextBytesWithSaltAndIv.Skip(16).Take(16).ToArray();
            // Get the actual cipher text bytes by removing the first 64 bytes from the cipherText string.
            var cipherTextBytes = cipherTextBytesWithSaltAndIv.Skip(32)
                .Take(cipherTextBytesWithSaltAndIv.Length - 32).ToArray();

            using (var password = new Rfc2898DeriveBytes(passPhrase, saltStringBytes, 1000))
            {
                var keyBytes = password.GetBytes(16);
                using (var symmetricKey = new RijndaelManaged())
                {
                    symmetricKey.BlockSize = 128;
                    symmetricKey.Mode = CipherMode.CBC;
                    symmetricKey.Padding = PaddingMode.PKCS7;
                    using (var decryptor = symmetricKey.CreateDecryptor(keyBytes, ivStringBytes))
                    {
                        using (var memoryStream = new MemoryStream(cipherTextBytes))
                        {
                            using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                            {
                                var plainTextBytes = new byte[cipherTextBytes.Length];
                                var decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
                                memoryStream.Close();
                                cryptoStream.Close();
                                return Encoding.UTF8.GetString(plainTextBytes, 0, decryptedByteCount);
                            }
                        }
                    }
                }
            }
        }

        private static byte[] Generate128BitsOfRandomEntropy()
        {
            var randomBytes = new byte[16]; // 16 Bytes will give us 256 bits.
            using (var rngCsp = new RNGCryptoServiceProvider())
            {
                // Fill the array with cryptographically secure random bytes.
                rngCsp.GetBytes(randomBytes);
            }
            return randomBytes;
        }

        public (string, DateTime) Authenticate(string userName, string password)
        {
            var sqlText = "SELECT * FROM Users WHERE UserName = @userName";
            using (var sqlCommand = new SqlCommand(sqlText, this.sqlConn))
            {
                sqlCommand.Parameters.AddWithValue("@userName", userName);
                this.sqlConn.Open();
                var sqlReader = sqlCommand.ExecuteReader();

                if (sqlReader.Read())
                {
                    var userRole = ((UserRolesEnum)sqlReader["RoleId"]).ToString();
                    var userKey = (string)sqlReader["Password"];
                    var dbPassword = UsersService.Decrypt(userKey, this.encryptionKey);

                    if (dbPassword.Equals(password))
                    {
                        return this.jwtAuthtentication.GetToken(userName, new[] { userRole });
                    }
                }
            }
            
            return (null, DateTime.MinValue);
        }

        public int ChangePaassword(string userName, string password)
        {
            var sqlText = @"UPDATE Users
                            SET Password = @password
                            WHERE UserName = @userName";
            var key = UsersService.Encrypt(password, this.encryptionKey);

            using (var sqlCommand = new SqlCommand(sqlText, sqlConn))
            {
                sqlCommand.Parameters.AddWithValue("@password", key);
                sqlCommand.Parameters.AddWithValue("@userName", userName);
                this.sqlConn.Open();
                return sqlCommand.ExecuteNonQuery();
            }
        }

        public int DeleteUser(long userId)
        {
            var sqlText = @"DELETE FROM Users
                            WHERE UserId = @userId";
            using (var sqlCommand = new SqlCommand(sqlText, sqlConn))
            {
                sqlCommand.Parameters.AddWithValue("@userId", userId);
                this.sqlConn.Open();
                return sqlCommand.ExecuteNonQuery();
            }
        }

        public void Dispose() => this.Dispose(true);

        public virtual void Dispose(bool disposing)
        {
            if (disposing)
                this.sqlConn.Dispose();
        }

        public User GetUserById(long userId)
        {
            var sqlText = @"SELECT UserId, Name, Surname, UserName, RoleId, IsDraw
                            FROM Users usr
                            WHERE UserId = @userId";
            using (var sqlCommand = new SqlCommand(sqlText, sqlConn))
            {
                sqlCommand.Parameters.AddWithValue("@userId", userId);
                this.sqlConn.Open();
                var sqlReader = sqlCommand.ExecuteReader();

                if (sqlReader.Read())
                    return new User
                    {
                        UserId = (long)sqlReader["UserId"],
                        Name = sqlReader["Name"] as string,
                        Surname = sqlReader["Surname"] as string,
                        UserName = sqlReader["UserName"] as string,
                        UserRole = ((UserRolesEnum)(int)sqlReader["RoleId"]).ToString(),
                        IsDraw = (bool)sqlReader["IsDraw"]
                    };

                return null;
            }
        }

        public IEnumerable<User> GetUsers(string name = "")
        {
            var sqlText = @"SELECT UserId, Name, Surname, UserName, RoleId, IsDraw
                            FROM Users usr
                            WHERE @name = '' OR @name IS NULL OR(Name + ' ' + Surname) LIKE '%' + @name + '%'";
            using (var sqlCommand = new SqlCommand(sqlText, sqlConn))
            {
                sqlCommand.Parameters.AddWithValue("@name", name);
                var sqlAdapter = new SqlDataAdapter(sqlCommand);
                var dt = new DataTable();
                sqlAdapter.Fill(dt);

                var users = new List<User>();
                foreach (DataRow dr in dt.Rows)
                {
                    users.Add(new User
                    {
                        UserId = (long)dr["UserId"],
                        Name = dr["Name"] as string,
                        Surname = dr["Surname"] as string,
                        UserName = dr["UserName"] as string,
                        UserRole = ((UserRolesEnum)(int)dr["RoleId"]).ToString(),
                        IsDraw = (bool)dr["IsDraw"]
                    });
                }

                return users;
            }
        }

        public long InsertUser(User user)
        {
            var sqlText = @"INSERT INTO Users (Name, Surname, UserName, RoleId, IsDraw)
                            VALUES(@name, @surname, @userName, @roleId, @isDraw)
                            SELECT @@IDENTITY";
            using (var sqlCommand = new SqlCommand(sqlText, sqlConn))
            {
                sqlCommand.Parameters.AddWithValue("@name", user.Name);
                sqlCommand.Parameters.AddWithValue("@surname", user.Surname);
                sqlCommand.Parameters.AddWithValue("@userName", user.UserName);
                sqlCommand.Parameters.AddWithValue("@roleId", (int)Enum.Parse(typeof(UserRolesEnum), user.UserRole));
                sqlCommand.Parameters.AddWithValue("@isDraw", user.IsDraw);
                this.sqlConn.Open();

                try
                {
                    return Convert.ToInt64(sqlCommand.ExecuteScalar());
                }
                catch (Exception ex)
                {
                    throw new AppException(ex.Message, "An unexpected error occurred while creating a new user", ex);
                }
            }
        }

        public int UpdateUser(User user)
        {
            var sqlText = @"UPDATE Users
                            SET Name = @name,
                                Surname = @surname,
                                RoleId = @roleId,
                                IsDraw = @isDraw
                            WHERE UserId = @userId";
            using (var sqlCommand = new SqlCommand(sqlText, sqlConn))
            {
                sqlCommand.Parameters.AddWithValue("@name", user.Name);
                sqlCommand.Parameters.AddWithValue("@surname", user.Surname);
                sqlCommand.Parameters.AddWithValue("@roleId", (int)Enum.Parse(typeof(UserRolesEnum), user.UserRole));
                sqlCommand.Parameters.AddWithValue("@isDraw", user.IsDraw);
                sqlCommand.Parameters.AddWithValue("@userId", user.UserId);
                this.sqlConn.Open();
                return sqlCommand.ExecuteNonQuery();
            }
        }
    }
}
