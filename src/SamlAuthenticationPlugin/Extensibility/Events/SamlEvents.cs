using PublicEntity = Telligent.Evolution.Extensibility.Api.Entities.Version1.User;
using Telligent.Services.SamlAuthenticationPlugin.Components;
using Telligent.Evolution.Extensibility.Events.Version1;

namespace Telligent.Services.SamlAuthenticationPlugin.Extensibility.Events
{
    public class SamlEvents: EventsBase, ISamlEventExecutor
    {
        //use a static singleton patter to avoid using internal telligent IServiceLoader
        private static SamlEvents instance;

        public static SamlEvents Instance
        {
            get
            {
                if (instance == null)
                {
                    instance = new SamlEvents();
                }
                return instance;
            }
        }

        private SamlEvents() : base()
        {
        }

        #region Authenticated

        private readonly object AfterAuthenticateEvent = new object();

        public event SamlAfterAuthenticateEventHandler AfterAuthenticate
        {
            add { Add(AfterAuthenticateEvent, value); }
            remove { Remove(AfterAuthenticateEvent, value); }
        }


        public void OnAfterAuthenticate(PublicEntity user, SamlTokenData samlTokenData)
        {
            SamlAfterAuthenticateEventArgs args = null;
            Execute<SamlAfterAuthenticateEventHandler>(AfterAuthenticateEvent, h =>
            {
                if (args == null)
                    args = new SamlAfterAuthenticateEventArgs(user, samlTokenData);
                h(args);

            }, false);

        }

        #endregion

        #region Create

        private readonly object AfterUserCreateEvent = new object();

        public event SamlAfterUserCreateEventHandler AfterCreate
        {
            add { Add(AfterUserCreateEvent, value); }
            remove { Remove(AfterUserCreateEvent, value); }
        }


        public void OnAfterUserCreate(PublicEntity user, SamlTokenData samlTokenData)
        {
            SamlAfterUserCreateEventArgs args = null;
            Execute<SamlAfterUserCreateEventHandler>(AfterAuthenticateEvent, h =>
            {
                if (args == null)
                    args = new SamlAfterUserCreateEventArgs(user, samlTokenData);
                h(args);

            }, false);

        }

        #endregion


    }
}
