using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using Telligent.Evolution.Extensibility;
using Telligent.Evolution.Extensibility.Api.Version1;
using Telligent.Services.SamlAuthenticationPlugin.Components;

namespace Telligent.Services.SamlAuthenticationPlugin
{
    /// <summary>
    /// Custom SqlDataProvider for Saml20AuthenticationPlugin
    /// </summary>
    public class SqlData
    {
        static readonly string databaseOwner = "dbo";
        private static IEventLog _apiEventLog;


        #region Helper methods & properties
        protected static SqlConnection GetSqlConnection()
        {

            try
            {
                return Apis.Get<IDatabaseConnections>().GetConnection("SiteSqlServer");
            }
            catch
            {
                throw new ArgumentException("SQL Connection String 'SiteSqlServer' is unavailable or invalid.");
            }

        }

        #endregion

        private SqlData()
        {
            _apiEventLog = Apis.Get<IEventLog>();
        }

        public static void SaveEncryptedSamlToken(Guid tokenKey, string encryptedData)
        {
            try
            {
                using (var conn = GetSqlConnection())
                {
                    var sql = $"INSERT INTO [{databaseOwner}].[db_SamlTempTokenData]" +
                              "(TokenKey" +
                              ", EncryptedData)" +
                              "VALUES" +
                              "(@TokenKey" +
                              ",@EncryptedData)";

                    var myCommand = new SqlCommand(sql, conn) { CommandType = CommandType.Text };

                    myCommand.Parameters.Add("@TokenKey", SqlDbType.UniqueIdentifier).Value = tokenKey;
                    myCommand.Parameters.Add("@EncryptedData", SqlDbType.NVarChar).Value = encryptedData;

                    conn.Open();
                    myCommand.ExecuteNonQuery();
                }
            }
            catch (Exception ex)
            {
                _apiEventLog.Write("Error inserting token into the db_SamlTempTokenData table. " + ex, new EventLogEntryWriteOptions() { Category = "SAML", EventId = 6023, EventType = "Error" });
            }
        }

        public static string GetTokenData(string tokenKey)
        {
            try
            {
                using (var conn = GetSqlConnection())
                {
                    var sql =
                        $"SELECT EncryptedData FROM [{databaseOwner}].[db_SamlTempTokenData] WHERE TokenKey = @TokenKey";

                    var command = new SqlCommand(sql, conn) { CommandType = CommandType.Text };

                    command.Parameters.Add("@TokenKey", SqlDbType.UniqueIdentifier).Value = Guid.Parse(tokenKey);
                    conn.Open();

                    return (string)command.ExecuteScalar();
                }
            }
            catch (Exception ex)
            {
                _apiEventLog.Write("Error reading from db_SamlTempTokenData; I dont think its installed. " + ex, new EventLogEntryWriteOptions() { Category = "SAML", EventId = 6022, EventType = "Error" });
                return string.Empty;
            }
        }

        public static void DeleteTokenData(string tokenKey)
        {
            try
            {
                using (var conn = GetSqlConnection())
                {
                    var sql =
                        $"DELETE FROM [{databaseOwner}].[db_SamlTempTokenData] WHERE TokenKey = @TokenKey";

                    var command = new SqlCommand(sql, conn) { CommandType = CommandType.Text };

                    command.Parameters.Add("@TokenKey", SqlDbType.UniqueIdentifier).Value = Guid.Parse(tokenKey);
                    conn.Open();
                    command.ExecuteNonQuery();
                }
            }
            catch (Exception ex)
            {
                _apiEventLog.Write("Error deleting from db_SamlTokenData; I dont think its installed. " + ex, new EventLogEntryWriteOptions() { Category = "SAML", EventId = 6024, EventType = "Error" });
            }
        }

        public static void SaveSamlToken(SamlTokenData samlTokenData)
        {
            if (!samlTokenData.IsExistingUser()) throw new InvalidOperationException("The User Id must be greater than zero.");

            if (GetSamlTokenStoreData(samlTokenData.UserId) == null)
                InsertSamlToken(samlTokenData);
            else
                UpdateSamlToken(samlTokenData);
        }

        public static SamlTokenData GetSamlTokenStoreData(int userId)
        {
            try
            {
                using (var myConnection = GetSqlConnection())
                {
                    var sql =
                        $@"SELECT top 1 SamlOAuthData FROM [{databaseOwner}].[db_SamlTokenStore] WHERE UserId = @userId ORDER BY ResponseDate Desc";

                    var myCommand = new SqlCommand(sql, myConnection) {CommandType = CommandType.Text};

                    myCommand.Parameters.Add("@userId", SqlDbType.Int).Value = userId;


                    // Execute the command
                    myConnection.Open();
                    var scalar = myCommand.ExecuteScalar();

                    if (scalar == null)
                        return null;

                    var oAuthData = SamlHelpers.Deserialize<SamlTokenData>(scalar.ToString());

                    return oAuthData;
                }
            }
            catch (Exception ex)
            {
                _apiEventLog.Write("Error reading from db_SamlTokenStore; I dont think its installed. " + ex, new EventLogEntryWriteOptions { Category= "SAML",  EventId =  6011, EventType="Error"});
            }

            return null;
        }

        #region Insert

        private static void InsertSamlToken(SamlTokenData oAuthData)
        {

            var oAuthDataXml = SamlHelpers.ConvertToString(oAuthData);

            InsertSamlToken(oAuthData.UserId, oAuthDataXml, oAuthData.ResponseDate, oAuthData.Email, oAuthData.NameId);
        }

        private static void InsertSamlToken(int userId, string oAuthData, DateTime responseDate, string email, string nameId)
        {
            try
            {
                using (var myConnection = GetSqlConnection())
                {
                    var sql =
                        $@"INSERT INTO [{databaseOwner}].[db_SamlTokenStore]
                           ([UserId]
                           ,[SamlOAuthData]
                           ,[ResponseDate]
                           ,[Email]
                           ,[ClientId])
                     VALUES
                           (@userId
                           ,@samlOAuthData
                           ,@responseDate
                           ,@email
                           ,@nameId)";

                    var myCommand = new SqlCommand(sql, myConnection) {CommandType = CommandType.Text};

                    myCommand.Parameters.Add("@userId", SqlDbType.Int).Value = userId;
                    myCommand.Parameters.Add("@samlOAuthData", SqlDbType.Text).Value = oAuthData;
                    myCommand.Parameters.Add("@responseDate", SqlDbType.DateTime).Value = responseDate;
                    myCommand.Parameters.Add("@email", SqlDbType.NVarChar).Value = email;
                    myCommand.Parameters.Add("@nameId", SqlDbType.NVarChar).Value = nameId;

                    // Execute the command
                    myConnection.Open();
                    myCommand.ExecuteNonQuery();

                }
            }
            catch (Exception ex)
            {
                _apiEventLog.Write("Error inserting token into the db_SamlTokenStore. " + ex, new EventLogEntryWriteOptions { Category = "SAML", EventId = 6009, EventType = "Error" });
            }
        }

        #endregion

        #region Update

        private static void UpdateSamlToken(SamlTokenData oAuthData)
        {

            var oAuthDataXml = SamlHelpers.ConvertToString(oAuthData);

            UpdateSamlToken(oAuthData.UserId, oAuthDataXml, oAuthData.ResponseDate, oAuthData.Email, oAuthData.NameId);
        }

        private static void UpdateSamlToken(int userId, string oAuthData, DateTime responseDate, string email, string nameId)
        {
            try
            {
                using (var myConnection = GetSqlConnection())
                {
                    var sql =
                        $@"UPDATE [{databaseOwner}].[db_SamlTokenStore] SET
                           [SamlOAuthData] = @samlOAuthData
                           ,[ResponseDate] = @responseDate
                           ,[Email] = @email
                           ,[ClientId] = @nameId
                           WHERE UserId = @userId";

                    var myCommand = new SqlCommand(sql, myConnection) {CommandType = CommandType.Text};

                    myCommand.Parameters.Add("@userId", SqlDbType.Int).Value = userId;
                    myCommand.Parameters.Add("@samlOAuthData", SqlDbType.Text).Value = oAuthData;
                    myCommand.Parameters.Add("@responseDate", SqlDbType.DateTime).Value = responseDate;
                    myCommand.Parameters.Add("@email", SqlDbType.NVarChar).Value = email;
                    myCommand.Parameters.Add("@nameId", SqlDbType.NVarChar).Value = nameId;

                    // Execute the command
                    myConnection.Open();
                    myCommand.ExecuteNonQuery();

                }
            }
            catch (Exception ex)
            {
                _apiEventLog.Write("Error updating from db_SamlTokenStore. " + ex, new EventLogEntryWriteOptions { Category = "SAML", EventId = 6010, EventType = "Error" });
            }
        }

        #endregion

        public static int DeleteSamlTokenData(int userId)
        {
            using (var myConnection = GetSqlConnection())
            {
                var sql = $@"DELETE FROM [{databaseOwner}].[db_SamlTokenStore] WHERE UserId = @userId";
                var myCommand = new SqlCommand(sql, myConnection) {CommandType = CommandType.Text};

                myCommand.Parameters.Add("@userId", SqlDbType.Int).Value = userId;

                // Execute the command
                myConnection.Open();
                return myCommand.ExecuteNonQuery();

            }
        }

        public static List<SamlTokenData> GetSamlTokenData(string nameId)
        {
            try
            {
                using (var myConnection = GetSqlConnection())
                {
                    var sql =
                        $@"SELECT SamlOAuthData FROM [{databaseOwner}].[db_SamlTokenStore] WHERE ClientId = @nameId";

                    var myCommand = new SqlCommand(sql, myConnection) {CommandType = CommandType.Text};

                    myCommand.Parameters.Add("@nameId", SqlDbType.NVarChar).Value = nameId;

                    var oAuthDatas = new List<SamlTokenData>();
                    // Execute the command
                    myConnection.Open();
                    using (var dr = myCommand.ExecuteReader())
                    {
                        while (dr.Read())
                        {
                            oAuthDatas.Add(SamlHelpers.Deserialize<SamlTokenData>(dr[0].ToString()));
                        }
                    }
                    return oAuthDatas;
                }
            }
            catch (Exception ex)
            {
                _apiEventLog.Write("Error reading from db_SamlTokenStore. " + ex, new EventLogEntryWriteOptions { Category= "SAML", EventId = 6012, EventType="Error"});
            }

            return null;
        }

        #region Install / Upgrade Pattern
        internal static bool IsInstalled()
        {
            return IsSamlTokenStoreInstalled() && IsSamlTokenDataInstalled();
        }

        internal static bool IsSamlTokenStoreInstalled()
        {
            using (var myConnection = GetSqlConnection())
            {
                var sql =
                    $@"select * from dbo.sysobjects where id = object_id(N'[{databaseOwner}].[db_SamlTokenStore]') and OBJECTPROPERTY(id, N'IsTable') = 1";

                var myCommand = new SqlCommand(sql, myConnection) {CommandType = CommandType.Text};

                // Execute the command
                myConnection.Open();
                var dr = myCommand.ExecuteReader();

                return dr.Read();

            }
        }

        internal static bool IsSamlTokenDataInstalled()
        {
            using (var conn = GetSqlConnection())
            {
                var sql =
                    $"SELECT * FROM dbo.sysobjects WHERE id = object_id(N'[{databaseOwner}].[db_SamlTempTokenData]') AND OBJECTPROPERTY(id, N'IsTable') = 1";

                var command = new SqlCommand(sql, conn) { CommandType = CommandType.Text };
                conn.Open();
                var dr = command.ExecuteReader();
                return dr.Read();
            }
        }

        internal static bool NeedsUpgrade()
        {
            return !HasEmailCol();
        }

        public static void Upgrade()
        {
            if (!HasEmailCol())
            {
                AddEmailCol();
                PopulateEmailCol();
                SetDefaultsEmailCol();
                AddEmailColKey();
            }
        }

        public static bool HasEmailCol()
        {
            using (var myConnection = GetSqlConnection())
            {
                var sql =
                    $@"select * from sys.columns where Name = N'Email' and Object_ID = object_id(N'[{databaseOwner}].[db_SamlTokenStore]')";
                var myCommand = new SqlCommand(sql, myConnection) {CommandType = CommandType.Text};

                // Execute the command
                myConnection.Open();
                var dr = myCommand.ExecuteReader();

                return dr.Read();
            }
        }

        public static int AddEmailCol()
        {
            using (var myConnection = GetSqlConnection())
            {
                var sql =
                    $@"ALTER TABLE [{databaseOwner}].[db_SamlTokenStore] ADD [ClientId] [nvarchar](256) NULL, [Email] [nvarchar](1024) NULL";
                var myCommand = new SqlCommand(sql, myConnection) {CommandType = CommandType.Text};

                // Execute the command
                myConnection.Open();
                return myCommand.ExecuteNonQuery();

            }
        }

        public static int PopulateEmailCol()
        {
            using (var myConnection = GetSqlConnection())
            {
                var sql =
                    $@"UPDATE [{databaseOwner}].[db_SamlTokenStore] SET Email = convert(XML,SUBSTRING([SamlOAuthData], 39, DATALENGTH([SamlOAuthData]))).value('(/SamlOAuthData/Email)[1]', 'varchar(1000)'), ClientId = convert(XML,SUBSTRING([SamlOAuthData], 39, DATALENGTH([SamlOAuthData]))).value('(/SamlOAuthData/ClientId)[1]', 'varchar(1000)')";
                var myCommand = new SqlCommand(sql, myConnection) {CommandType = CommandType.Text};

                // Execute the command
                myConnection.Open();
                return myCommand.ExecuteNonQuery();

            }
        }

        public static int SetDefaultsEmailCol()
        {
            using (var myConnection = GetSqlConnection())
            {
                var sql1 =
                    $@"ALTER TABLE [{databaseOwner}].[db_SamlTokenStore] ALTER COLUMN [ClientId] [nvarchar](256) NOT NULL";
                var sql2 =
                    $@"ALTER TABLE [{databaseOwner}].[db_SamlTokenStore] ALTER COLUMN [Email] [nvarchar](1024) NOT NULL";
                var myCommand1 = new SqlCommand(sql1, myConnection) {CommandType = CommandType.Text};

                var myCommand2 = new SqlCommand(sql2, myConnection) {CommandType = CommandType.Text};

                // Execute the command
                myConnection.Open();
                return myCommand1.ExecuteNonQuery() + myCommand2.ExecuteNonQuery();
            }
        }

        public static int AddEmailColKey()
        {
            using (var myConnection = GetSqlConnection())
            {
                var sql = $@"ALTER TABLE [{databaseOwner}].[db_SamlTokenStore] DROP CONSTRAINT [PK_db_SamlTokenStore]";
                var myCommand = new SqlCommand(sql, myConnection) {CommandType = CommandType.Text};

                var sql2 =
                    $@"ALTER TABLE [{databaseOwner}].[db_SamlTokenStore] ADD CONSTRAINT [PK_db_SamlTokenStore] PRIMARY KEY CLUSTERED 
					                                        (
						                                        [UserId] ASC,
						                                        [ClientId] ASC
					                                        )ON [PRIMARY]";
                var myCommand2 = new SqlCommand(sql2, myConnection);
                myCommand2.CommandType = CommandType.Text;

                var sql3 = $@"CREATE INDEX [IX_db_SamlTokenStore_UserId] ON [{databaseOwner}].[db_SamlTokenStore]
                                                                (
	                                                                [UserId], [ResponseDate] DESC
                                                                ) ON [PRIMARY]";

                var myCommand3 = new SqlCommand(sql3, myConnection) {CommandType = CommandType.Text};

                // Execute the command
                myConnection.Open();
                return myCommand.ExecuteNonQuery() + myCommand2.ExecuteNonQuery() + myCommand3.ExecuteNonQuery();
            }
        }

        internal static void Install()
        {
            if (!IsSamlTokenStoreInstalled())
                InstallSamlTokenStore();

            if (!IsSamlTokenDataInstalled())
                InstallSamlTokenDataStore();
        }

        internal static int InstallSamlTokenStore()
        {
            using (var myConnection = GetSqlConnection())
            {
                var sql1 = $@"CREATE TABLE [{databaseOwner}].[db_SamlTokenStore](
	                    [UserId] [int] NOT NULL,
                        [ClientId] [varchar](256) NOT NULL, 
                        [Email] [nvarchar](1024) NOT NULL,
	                    [SamlOAuthData] [text] NOT NULL,
	                    [ResponseDate] [datetime] NOT NULL,
                    CONSTRAINT [PK_db_SamlTokenStore] PRIMARY KEY CLUSTERED 
                    (
	                    [UserId] ASC,
						[ClientId] ASC
                    ) ON [PRIMARY],
                    CONSTRAINT [UC_db_SamlTokenStore_ClientId] UNIQUE NONCLUSTERED 
                    (
                        [ClientId] ASC
                    ) ON [PRIMARY]);CREATE INDEX [IX_db_SamlTokenStore_UserId] ON [{databaseOwner}].[db_SamlTokenStore]
                    (
	                    [UserId], [ResponseDate] DESC
                    )ON [PRIMARY]";

                var myCommand1 = new SqlCommand(sql1, myConnection) {CommandType = CommandType.Text};

                // Execute the command
                myConnection.Open();
                return myCommand1.ExecuteNonQuery();
            }
        }

        internal static int InstallSamlTokenDataStore()
        {
            using (var conn = GetSqlConnection())
            {
                var sql =
                    $"CREATE TABLE [{databaseOwner}].[db_SamlTempTokenData]([TokenKey] [uniqueidentifier] NOT NULL, [EncryptedData] [text] NOT NULL) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]";

                var command = new SqlCommand(sql, conn) { CommandType = CommandType.Text };
                conn.Open();
                return command.ExecuteNonQuery();
            }
        }

        #endregion
    }
}

