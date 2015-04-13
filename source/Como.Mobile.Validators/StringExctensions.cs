namespace Como.Mobile.Validators
{
    public static class StringsExctensions
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