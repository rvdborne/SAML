using Telligent.Evolution.Extensibility.Events.Version1;
using Telligent.Services.SamlAuthenticationPlugin.Components;
using PublicEntity = Telligent.Evolution.Extensibility.Api.Entities.Version1.User;

namespace Telligent.Services.SamlAuthenticationPlugin.Extensibility.Events
{
    public class SamlEvents : EventsBase, ISamlEventExecutor
    {
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

        public SamlEvents() { }

        #region Authenticated
        private readonly object AfterAuthenticateEvent = new object();
        public event SamlAfterAuthenticateEventHandler AfterAuthenticate
        {
            add => Add(AfterAuthenticateEvent, value);
            remove => Remove(AfterAuthenticateEvent, value);
        }

        public void OnAfterAuthenticate(PublicEntity user, SamlTokenData samlTokenData)
        {            
            Get<SamlAfterAuthenticateEventHandler>(this)?.Invoke(new SamlAfterAuthenticateEventArgs(user, samlTokenData));
        }

        #endregion

        #region Create

        private readonly object AfterUserCreateEvent = new object();

        public event SamlAfterUserCreateEventHandler AfterCreate
        {
            add => Add(AfterUserCreateEvent, value);
            remove => Remove(AfterUserCreateEvent, value);
        }

        public void OnAfterUserCreate(PublicEntity user, SamlTokenData samlTokenData)
        {

            Get<SamlAfterUserCreateEventHandler>(this)?.Invoke(new SamlAfterUserCreateEventArgs(user, samlTokenData));
        }

        #endregion
    }   
}