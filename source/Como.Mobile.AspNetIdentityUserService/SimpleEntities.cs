/*
 * Copyright 2014 Dominick Baier, Brock Allen
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using System;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Constants = Thinktecture.IdentityServer.Core.Constants;

namespace Como.Mobile.AspNetIdentityUserService
{
    public class User : IdentityUser
    {
        public User()
        {
            CreateDate = DateTime.Now;
            IsApproved = false;
            LastLoginDate = DateTime.Now;
            LastActivityDate = DateTime.Now;
            LastPasswordChangedDate = DateTime.Now;
            LastLockoutDate = DateTime.Parse("1/1/1754");
            FailedPasswordAnswerAttemptWindowStart = DateTime.Parse("1/1/1754");
            FailedPasswordAttemptWindowStart = DateTime.Parse("1/1/1754");
        }

        public Guid ApplicationId { get; set; }
        public string MobileAlias { get; set; }
        public bool IsAnonymous { get; set; }
        public DateTime LastActivityDate { get; set; }
        public string MobilePIN { get; set; }
        public string LoweredEmail { get; set; }
        public string LoweredUserName { get; set; }
        public string PasswordQuestion { get; set; }
        public string PasswordAnswer { get; set; }
        public bool IsApproved { get; set; }
        public bool IsLockedOut { get; set; }
        public DateTime CreateDate { get; set; }
        public DateTime LastLoginDate { get; set; }
        public DateTime LastPasswordChangedDate { get; set; }
        public DateTime LastLockoutDate { get; set; }
        public int FailedPasswordAttemptCount { get; set; }
        public DateTime FailedPasswordAttemptWindowStart { get; set; }
        public int FailedPasswordAnswerAttemptCount { get; set; }
        public DateTime FailedPasswordAnswerAttemptWindowStart { get; set; }
        public string Comment { get; set; }
    }

    public class Role : IdentityRole
    {
    }

    public class Context : IdentityDbContext<User, Role, string, IdentityUserLogin, IdentityUserRole, IdentityUserClaim>
    {
        public Context(string connString)
            : base(connString)
        {
        }
    }

    public class UserStore : UserStore<User, Role, string, IdentityUserLogin, IdentityUserRole, IdentityUserClaim>
    {
        public UserStore(Context ctx)
            : base(ctx)
        {
        }
    }

    public class UserManager : UserManager<User, string>
    {
        public UserManager(UserStore store)
            : base(store)
        {
            PasswordHasher = new SqlPasswordHasher();
            ClaimsIdentityFactory = new ClaimsFactory();
        }
    }

    public class ClaimsFactory : ClaimsIdentityFactory<User, string>
    {
        public ClaimsFactory()
        {
            UserIdClaimType = Constants.ClaimTypes.Subject;
            UserNameClaimType = Constants.ClaimTypes.PreferredUserName;
            RoleClaimType = Constants.ClaimTypes.Role;
        }

        public override async Task<ClaimsIdentity> CreateAsync(UserManager<User, string> manager, User user,
            string authenticationType)
        {
            // Note the authenticationType must match the one defined in
            ClaimsIdentity userIdentity =
                await manager.CreateIdentityAsync(user, DefaultAuthenticationTypes.ApplicationCookie);
            // Add custom user claims here
            return userIdentity;
        }
    }

    public class RoleStore : RoleStore<Role>
    {
        public RoleStore(Context ctx)
            : base(ctx)
        {
        }
    }

    public class RoleManager : RoleManager<Role>
    {
        public RoleManager(RoleStore store)
            : base(store)
        {
        }
    }
}