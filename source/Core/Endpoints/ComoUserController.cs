using System;
using System.ComponentModel;
using System.Net;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web.Http;
using Como.Mobile.Idsrv.Entities;
using Microsoft.AspNet.Identity;
using Thinktecture.IdentityServer.Core.Logging;

namespace Thinktecture.IdentityServer.Core.Endpoints
{
    [EditorBrowsable(EditorBrowsableState.Never)]
    public class ComoUserController : ApiController
    {
        private readonly UserManager _userManager;
        private readonly static ILog Logger = LogProvider.GetCurrentClassLogger();

        /// <summary>
        /// </summary>
        /// <param name="userManager"></param>
        /// <exception cref="ArgumentNullException"></exception>
        public ComoUserController(UserManager userManager)
        {
            if (userManager == null) throw new ArgumentNullException("userManager");
            _userManager = userManager;
        }

        [Route(Constants.RoutePaths.ResetPasswordRequest)]
        [HttpGet]
        public async Task<IHttpActionResult> ResetPasswordRequest(string email)
        {
            if (String.IsNullOrEmpty(email) || IsValidEmail(email) == false)
            {
                return BadRequest("Email not valid.");
            }
            User user = await _userManager.FindByNameAsync(email);
            if (user == null)
            {
                // Don't reveal that the user does not exist or is not confirmed
                return Ok();
            }
            string token = await _userManager.GeneratePasswordResetTokenAsync(user.Id);
            var response = _userManager.SendPasswordRecoveryEmail(email, token, null);
            return Ok(response);
        }

        [Route(Constants.RoutePaths.ResetPassword)]
        [HttpGet]
        public async Task<IHttpActionResult> ResetPassword(string email, string newPassword, string token)
        {
            try
            {
                IdentityResult identityResult = await _userManager.ResetPasswordAsync(email, newPassword, token);

                if (identityResult.Succeeded)
                {
                    return Ok();
                }
                foreach (var exception in identityResult.Errors)
                {
                    Logger.Error(exception);
                }
                return InternalServerError();
            }
            catch (Exception ex)
            {
                Logger.Error(ex.Message);
                throw new HttpResponseException(HttpStatusCode.InternalServerError);
            }
        }


        private bool IsValidEmail(string email)
        {
            try
            {
                return Regex.IsMatch(email,
                    @"^(?("")("".+?(?<!\\)""@)|(([0-9a-z]((\.(?!\.))|[-!#\$%&'\*\+/=\?\^`\{\}\|~\w])*)(?<=[0-9a-z])@))" +
                    @"(?(\[)(\[(\d{1,3}\.){3}\d{1,3}\])|(([0-9a-z][-\w]*[0-9a-z]*\.)+[a-z0-9][\-a-z0-9]{0,22}[a-z0-9]))$",
                    RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(250));
            }
            catch (RegexMatchTimeoutException)
            {
                return false;
            }
        }
    }
}