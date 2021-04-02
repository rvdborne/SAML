using System;
using System.Collections.Generic;
using System.Web;

namespace Verint.Services.SamlAuthenticationPlugin.Components
{

    public static class CookieHelper
    {
        public static void AddCookie(HttpCookie cookie)
        {
            if (CookieCutter.IsOversizedCookie(cookie))
                CookieCutter.AddCutCookie(cookie);
            else
                HttpContext.Current.Response.Cookies.Add(cookie);

        }
        public static void DeleteCookie(string cookieName)
        {
            HttpCookie cookie = HttpContext.Current.Request.Cookies[cookieName];
            if (cookie != null)
            {
                if (CookieCutter.IsCutCookie(cookie))
                    CookieCutter.DeleteCutCookie(cookie);
                else
                    deleteCookie(cookie);
            }
        }
        internal static void deleteCookie(HttpCookie cookie)
        {
            if (cookie != null)
            {
                HttpContext.Current.Response.Cookies.Remove(cookie.Name);
                cookie.Expires = DateTime.Now.AddDays(-1);
                cookie.Value = null;
                HttpContext.Current.Response.SetCookie(cookie);
            }
        }
        public static HttpCookie GetCookie(string cookieName)
        {
            HttpCookie cookie = HttpContext.Current.Request.Cookies[cookieName];
            if (cookie != null)
            {
                if (CookieCutter.IsCutCookie(cookie))
                    return CookieCutter.GetUnCutCookie(cookie);
                
                return cookie;
            }

            return null;
        }
    }

    /// <summary>
    /// Breaks down oversized cookies into smaller ones
    /// </summary>
    internal static class CookieCutter
    {
        const int MaxCookieBytes = 4000;
        const string cookieCutsKey = "cookieCuts";
        const string cookieCutKeyPattern = "cookieCut-{0}";

        public static bool IsCutCookie(HttpCookie cookie)
        {
            int cuts = 0;

            return int.TryParse(cookie[cookieCutsKey], out cuts);
        }

        public static bool IsOversizedCookie(HttpCookie cookie)
        {
            if (cookie.Value != null)
                return cookie.Value.Length > MaxCookieBytes;

            return false; //note this code path doesnt test cookies with multiple values.

        }

        public static void AddCutCookie(HttpCookie oversizedCookie)
        {
            HttpCookie indexCookie = NewCookieCopySettings(oversizedCookie.Name, oversizedCookie);

            var cuts = new List<string>(CutString(oversizedCookie.Value, MaxCookieBytes));
            indexCookie[cookieCutsKey] = cuts.Count.ToString();

            for (int i = 0; i < cuts.Count; i++)
            {
                indexCookie[string.Format(cookieCutKeyPattern, i+1)] = AddCookiePiece(indexCookie, i + 1, cuts[i]);
            }

            HttpContext.Current.Response.Cookies.Add(indexCookie);

        }

        public static string AddCookiePiece(HttpCookie indexCookie, int pieceNumber, string cutValue)
        {
            HttpCookie cookiePiece = NewCookieCopySettings(indexCookie.Name + "-" + pieceNumber, indexCookie);

            cookiePiece.Value = cutValue;

            HttpContext.Current.Response.Cookies.Add(cookiePiece);

            return cookiePiece.Name;
        }

        static IEnumerable<string> CutString(string str, int maxLength)
        {
            for (int i = 0; i < str.Length; i += maxLength)
                yield return str.Substring(i, Math.Min(maxLength, str.Length - i));
        }

        public static void DeleteCutCookie(HttpCookie cookie)
        {
            //delete the parts
            int cuts = int.Parse(cookie[cookieCutsKey]);
            for (int i = 1; i <= cuts; i++)
            {
                var cookiePartName = cookie[string.Format(cookieCutKeyPattern, i)];
                CookieHelper.DeleteCookie(cookiePartName);
            }

            //delete the index cookie
            CookieHelper.deleteCookie(cookie);

        }

        public static HttpCookie GetUnCutCookie(HttpCookie cookie)
        {
            //note this code assumes the parts are only using a single value not values

            var uncutCookie = NewCookieCopySettings(cookie.Name, cookie);

            int cuts = int.Parse(cookie[cookieCutsKey]);
            string value = string.Empty;
            for (int i = 1; i <= cuts; i++)
            {
                var cookiePartName = cookie[string.Format(cookieCutKeyPattern, i)];
                HttpCookie cookiePart = HttpContext.Current.Request.Cookies[cookiePartName];
                if (cookiePart == null)
                    throw new NullReferenceException("All cookie parts could not be found, cookie could not be reassembled");

                value = value + cookiePart.Value;
            }

            uncutCookie.Value = value;

            return uncutCookie;

        }

        private static HttpCookie NewCookieCopySettings(string newCookieName, HttpCookie referenceCookie)
        {
            var newCookie = new HttpCookie(newCookieName);

            newCookie.Domain = referenceCookie.Domain;
            newCookie.Expires = referenceCookie.Expires;
            newCookie.HttpOnly = referenceCookie.HttpOnly;
            newCookie.Path = referenceCookie.Path;
            newCookie.Secure = referenceCookie.Secure;
            newCookie.Shareable = referenceCookie.Shareable;

            return newCookie;
        }

    }
}
