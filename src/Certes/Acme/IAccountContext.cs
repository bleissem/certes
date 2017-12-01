﻿using Certes.Acme.Resource;
using Certes.Jws;
using Certes.Pkcs;
using System;
using System.Threading.Tasks;
using System.Collections.Generic;

namespace Certes.Acme
{
    /// <summary>
    /// Supports ACME account operations.
    /// </summary>
    public interface IAccountContext
    {
        /// <summary>
        /// Gets the account resource.
        /// </summary>
        /// <returns>The account resource.</returns>
        Task<Account> Resource();

        /// <summary>
        /// Gets the orders
        /// </summary>
        /// <returns>The orders.</returns>
        Task<IOrderListContext> Orders();

        /// <summary>
        /// Updates the specified agree terms of service.
        /// </summary>
        /// <param name="agreeTermsOfService">if set to <c>true</c> [agree terms of service].</param>
        /// <param name="contact">The contact.</param>
        /// <returns></returns>
        Task<IAccountContext> Update(bool agreeTermsOfService = false, IEnumerable<string> contact = null);

        /// <summary>
        /// Deactivates the current account.
        /// </summary>
        /// <returns>The awaitable.</returns>
        Task<Account> Deactivate();
    }
}