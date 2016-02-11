using System;
using System.Collections;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using Telligent.Evolution.Extensibility.Api.Version1;
using Telligent.Services.SamlAuthenticationPlugin.Components;

namespace Telligent.Services.SamlAuthenticationPlugin
{
    /// <summary>
    /// Custom SqlDataProvider for Saml20AuthenticationPlugin
    /// </summary>
    public class SqlData
    {
        static string databaseOwner = "dbo";


        #region Helper methods & properties
        protected static SqlConnection GetSqlConnection()
        {

            try
            {
                return PublicApi.DatabaseConnections.GetConnection("SiteSqlServer");
            }
            catch
            {
                throw new ArgumentException("SQL Connection String 'SiteSqlServer' is unavailable or invalid.");
            }

        }

        #endregion

        private SqlData()
        { }

        public static void SaveSamlToken(SamlTokenData samlTokenData)
        {
            if (!samlTokenData.IsExistingUser()) throw new InvalidOperationException("The User Id must be greater than zero.");

            if (GetSamlTokenData(samlTokenData.UserId) == null)
                InsertSamlToken(samlTokenData);
            else
                UpdateSamlToken(samlTokenData);
        }

        public static SamlTokenData GetSamlTokenData(int userId)
        {
            try
            {
                using (SqlConnection myConnection = GetSqlConnection())
                {
                    string sql =
                        string.Format(@"SELECT top 1 SamlOAuthData FROM [{0}].[db_SamlTokenStore] WHERE UserId = @userId ORDER BY ResponseDate Desc",
                                      databaseOwner);

                    SqlCommand myCommand = new SqlCommand(sql, myConnection);
                    myCommand.CommandType = CommandType.Text;

                    myCommand.Parameters.Add("@userId", SqlDbType.Int).Value = userId;


                    // Execute the command
                    myConnection.Open();
                    object scalar = myCommand.ExecuteScalar();

                    if (scalar == null)
                        return null;

                    var oAuthData = SamlHelpers.Deserialize<SamlTokenData>(scalar.ToString());

                    return oAuthData;
                }
            }
            catch (Exception ex)
            {
                PublicApi.Eventlogs.Write("Error reading from db_SamlTokenStore; I dont think its installed. " + ex.ToString(), new EventLogEntryWriteOptions(){ Category= "SAML",  EventId =  6011, EventType="Error"});
            }

            return null;
        }

        #region Insert

        private static void InsertSamlToken(SamlTokenData oAuthData)
        {

            string oAuthDataXml = SamlHelpers.ConvertToString(oAuthData);

            InsertSamlToken(oAuthData.UserId, oAuthDataXml, oAuthData.ResponseDate, oAuthData.Email, oAuthData.NameId);
        }


        private static void InsertSamlToken(int userId, string oAuthData, DateTime responseDate, string email, string nameId)
        {
            try
            {
                using (SqlConnection myConnection = GetSqlConnection())
                {
                    string sql =
                        string.Format(
                            @"INSERT INTO [{0}].[db_SamlTokenStore]
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
                           ,@nameId)",
                            databaseOwner);

                    SqlCommand myCommand = new SqlCommand(sql, myConnection);
                    myCommand.CommandType = CommandType.Text;

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
                PublicApi.Eventlogs.Write("Error inserting token into the db_SamlTokenStore. " + ex.ToString(), new EventLogEntryWriteOptions() { Category = "SAML", EventId = 6009, EventType = "Error" });
            }

        }


        private static void InsertSamlLink(int userId, string clientUserId)
        {
            try
            {
                using (SqlConnection myConnection = GetSqlConnection())
                {
                    string sql =
                        string.Format(
                            @"INSERT INTO [{0}].[db_Saml_Links]
                                   ([UserId]
                                   ,[ClientType]
                                   ,[ClientUserId])
                             VALUES
                                   (@userId
                                   ,@clientType
                                   ,@clientUserId)",
                            databaseOwner);

                    SqlCommand myCommand = new SqlCommand(sql, myConnection);
                    myCommand.CommandType = CommandType.Text;

                    myCommand.Parameters.Add("@userId", SqlDbType.Int).Value = userId;
                    myCommand.Parameters.Add("@clientUserId", SqlDbType.NVarChar).Value = clientUserId;
                    myCommand.Parameters.Add("@clientType", SqlDbType.NVarChar).Value = "SAML";

                    // Execute the command
                    myConnection.Open();
                    myCommand.ExecuteNonQuery();

                }
            }
            catch (Exception ex)
            {
                PublicApi.Eventlogs.Write("Error inserting token into the db_SAML_Links. " + ex.ToString(), new EventLogEntryWriteOptions() { Category = "SAML", EventId = 6009, EventType = "Error" });
            }

        }

        #endregion

        #region Update

        private static void UpdateSamlToken(SamlTokenData oAuthData)
        {

            string oAuthDataXml = SamlHelpers.ConvertToString(oAuthData);

            UpdateSamlToken(oAuthData.UserId, oAuthDataXml, oAuthData.ResponseDate, oAuthData.Email, oAuthData.NameId);
        }

        private static void UpdateSamlToken(int userId, string oAuthData, DateTime responseDate, string email, string nameId)
        {
            try
            {
                using (SqlConnection myConnection = GetSqlConnection())
                {
                    string sql =
                        string.Format(
                            @"UPDATE [{0}].[db_SamlTokenStore] SET
                           [SamlOAuthData] = @samlOAuthData
                           ,[ResponseDate] = @responseDate
                           ,[Email] = @email
                           ,[ClientId] = @nameId
                           WHERE UserId = @userId",
                            databaseOwner);

                    SqlCommand myCommand = new SqlCommand(sql, myConnection);
                    myCommand.CommandType = CommandType.Text;

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
                PublicApi.Eventlogs.Write("Error updating from db_SamlTokenStore. " + ex.ToString(), new EventLogEntryWriteOptions() { Category = "SAML", EventId = 6010, EventType = "Error" });
            }

       }

        #endregion


        private static int DeleteSamlTokenData(int userId)
        {
            using (SqlConnection myConnection = GetSqlConnection())
            {
                string sql = string.Format(@"DELETE FROM [{0}].[db_SamlTokenStore] WHERE UserId = @userId", databaseOwner);
                var myCommand = new SqlCommand(sql, myConnection);
                myCommand.CommandType = CommandType.Text;

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
                using (SqlConnection myConnection = GetSqlConnection())
                {
                    string sql =
                        string.Format(@"SELECT SamlOAuthData FROM [{0}].[db_SamlTokenStore] WHERE ClientId = @nameId",
                                      databaseOwner);

                    SqlCommand myCommand = new SqlCommand(sql, myConnection);
                    myCommand.CommandType = CommandType.Text;

                    myCommand.Parameters.Add("@nameId", SqlDbType.NVarChar).Value = nameId;

                    List<SamlTokenData> oAuthDatas = new List<SamlTokenData>();
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
                PublicApi.Eventlogs.Write("Error reading from db_SamlTokenStore. " + ex.ToString(), new EventLogEntryWriteOptions(){ Category= "SAML", EventId = 6012, EventType="Error"});
            }

            return null;
        }

        #region Install / Upgrade Pattern
        internal static bool IsInstalled()
        {
            return IsSamlTokenStoreInstalled();
        }
        internal static bool IsSamlTokenStoreInstalled()
        {
            using (SqlConnection myConnection = GetSqlConnection())
            {
                string sql = string.Format(@"select * from dbo.sysobjects where id = object_id(N'[{0}].[db_SamlTokenStore]') and OBJECTPROPERTY(id, N'IsTable') = 1", databaseOwner);

                SqlCommand myCommand = new SqlCommand(sql, myConnection);
                myCommand.CommandType = CommandType.Text;

                // Execute the command
                myConnection.Open();
                SqlDataReader dr = myCommand.ExecuteReader();

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
            using (SqlConnection myConnection = GetSqlConnection())
            {
                string sql = string.Format(@"select * from sys.columns where Name = N'Email' and Object_ID = object_id(N'[{0}].[db_SamlTokenStore]')", databaseOwner);
                SqlCommand myCommand = new SqlCommand(sql, myConnection);
                myCommand.CommandType = CommandType.Text;

                // Execute the command
                myConnection.Open();
                SqlDataReader dr = myCommand.ExecuteReader();

                return dr.Read();
            }
        }

        public static int AddEmailCol()
        {
            using (SqlConnection myConnection = GetSqlConnection())
            {
                string sql = string.Format(@"ALTER TABLE [{0}].[db_SamlTokenStore] ADD [ClientId] [nvarchar](256) NULL, [Email] [nvarchar](1024) NULL", databaseOwner);
                SqlCommand myCommand = new SqlCommand(sql, myConnection);
                myCommand.CommandType = CommandType.Text;

                // Execute the command
                myConnection.Open();
                return myCommand.ExecuteNonQuery();

            }
        }

        public static int PopulateEmailCol()
        {
            using (SqlConnection myConnection = GetSqlConnection())
            {
                string sql = string.Format(@"UPDATE [{0}].[db_SamlTokenStore] SET Email = convert(XML,SUBSTRING([SamlOAuthData], 39, DATALENGTH([SamlOAuthData]))).value('(/SamlOAuthData/Email)[1]', 'varchar(1000)'), ClientId = convert(XML,SUBSTRING([SamlOAuthData], 39, DATALENGTH([SamlOAuthData]))).value('(/SamlOAuthData/ClientId)[1]', 'varchar(1000)')", databaseOwner);
                SqlCommand myCommand = new SqlCommand(sql, myConnection);
                myCommand.CommandType = CommandType.Text;

                // Execute the command
                myConnection.Open();
                return myCommand.ExecuteNonQuery();

            }
        }

        public static int SetDefaultsEmailCol()
        {
            using (SqlConnection myConnection = GetSqlConnection())
            {
                string sql1 = string.Format(@"ALTER TABLE [{0}].[db_SamlTokenStore] ALTER COLUMN [ClientId] [nvarchar](256) NOT NULL", databaseOwner);
                string sql2 = string.Format(@"ALTER TABLE [{0}].[db_SamlTokenStore] ALTER COLUMN [Email] [nvarchar](1024) NOT NULL", databaseOwner);
                SqlCommand myCommand1 = new SqlCommand(sql1, myConnection);
                myCommand1.CommandType = CommandType.Text;

                SqlCommand myCommand2 = new SqlCommand(sql2, myConnection);
                myCommand2.CommandType = CommandType.Text;

                // Execute the command
                myConnection.Open();
                return myCommand1.ExecuteNonQuery() + myCommand2.ExecuteNonQuery();
            }
        }


        public static int AddEmailColKey()
        {
            using (var myConnection = GetSqlConnection())
            {
                var sql = string.Format(@"ALTER TABLE [{0}].[db_SamlTokenStore] DROP CONSTRAINT [PK_db_SamlTokenStore]", databaseOwner);
                var myCommand = new SqlCommand(sql, myConnection);
                myCommand.CommandType = CommandType.Text;

                var sql2 = string.Format(@"ALTER TABLE [{0}].[db_SamlTokenStore] ADD CONSTRAINT [PK_db_SamlTokenStore] PRIMARY KEY CLUSTERED 
					                                        (
						                                        [UserId] ASC,
						                                        [ClientId] ASC
					                                        )ON [PRIMARY],
					                                        UNIQUE NONCLUSTERED 
					                                        (
						                                        [ClientId] ASC
					                                        ) ON [PRIMARY]", databaseOwner);
                var myCommand2 = new SqlCommand(sql2, myConnection);
                myCommand2.CommandType = CommandType.Text;

                var sql3 = string.Format(@"CREATE INDEX [IX_db_SamlTokenStore_UserId] ON [{0}].[db_SamlTokenStore]
                                                                (
	                                                                [UserId], [ResponseDate] DESC
                                                                ) ON [PRIMARY]", databaseOwner);

                var myCommand3 = new SqlCommand(sql3, myConnection);
                myCommand3.CommandType = CommandType.Text;



                // Execute the command
                myConnection.Open();
                return myCommand.ExecuteNonQuery() + myCommand2.ExecuteNonQuery() + myCommand3.ExecuteNonQuery();

            }
        }


        internal static void Install()
        {
            if(!IsSamlTokenStoreInstalled())
                InstallSamlTokenStore();
        }

        internal static int InstallSamlTokenStore()
        {
            using (SqlConnection myConnection = GetSqlConnection())
            {
                var sql1 = string.Format(@"CREATE TABLE [{0}].[db_SamlTokenStore](
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
                    UNIQUE NONCLUSTERED 
                    (
                        [ClientId] ASC
                    ) ON [PRIMARY]);CREATE INDEX [IX_db_SamlTokenStore_UserId] ON [{0}].[db_SamlTokenStore]
                    (
	                    [UserId], [ResponseDate] DESC
                    )ON [PRIMARY]", databaseOwner);

                var myCommand1 = new SqlCommand(sql1, myConnection);
                myCommand1.CommandType = CommandType.Text;

                // Execute the command
                myConnection.Open();
                return myCommand1.ExecuteNonQuery();

            }
        }
        


        #endregion

    }


}

