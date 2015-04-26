namespace Como.Mobile.Idsrv.Validators
{
    public static class StringsExtensions
    {
        public static string EnsureTrailingSlash(this string url)
        {
            if (!url.EndsWith("/"))
            {
                return url + "/";
            }

            return url;
        }
    }
}