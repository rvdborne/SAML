CREATE TABLE [dbo].[db_SamlTokenStore](
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
                    ) ON [PRIMARY]);CREATE INDEX [IX_db_SamlTokenStore_UserId] ON [dbo].[db_SamlTokenStore]
                    (
	                    [UserId], [ResponseDate] DESC
                    )ON [PRIMARY]