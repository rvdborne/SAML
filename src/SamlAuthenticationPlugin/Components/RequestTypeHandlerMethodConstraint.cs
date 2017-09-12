using System.Collections.Generic;
using System.Web.Routing;
using Telligent.Evolution.Extensibility.Urls.Version1;

namespace Telligent.Services.SamlAuthenticationPlugin.Components
{
    public class RequestTypeHandlerMethodConstraint : IComparableRouteConstraint, IRouteConstraint
    {

        private List<string> _verbs = null;

        public string[] Verbs
        {
            get { return _verbs.ToArray(); }
        }
        public RequestTypeHandlerMethodConstraint(params string[] verbs)
        {
            var verbsList = new List<string>();
            foreach (string verb in verbs)
                verbsList.Add(verb.ToUpperInvariant());

            _verbs = verbsList;
        }
        public bool IsEqual(IComparableRouteConstraint constraint)
        {
            var inCstrt = constraint as RequestTypeHandlerMethodConstraint;
            if (inCstrt == null) return false;

            return _verbs.Equals(Verbs);
        }

        public bool Match(System.Web.HttpContextBase httpContext, System.Web.Routing.Route route, string parameterName, System.Web.Routing.RouteValueDictionary values, System.Web.Routing.RouteDirection routeDirection)
        {
            var inMethod = httpContext.Request.HttpMethod.ToUpperInvariant();
            return _verbs.Contains(inMethod);
        }
    }
}
