﻿using System;
using System.Collections.Generic;
using System.CommandLine;
using Certes.Cli.Options;

using ValidationFunc = System.Func<Certes.Cli.Options.AccountOptions, bool>;

namespace Certes.Cli.Processors
{
    internal class AccountCommand
    {
        private static readonly List<(AccountAction Action, ValidationFunc IsValid, string Help)> validations = new List<(AccountAction, ValidationFunc, string)>
        {
            (AccountAction.New, (ValidationFunc)(o => !string.IsNullOrWhiteSpace(o.Email)), "Please enter the admin email."),
            (AccountAction.Update, (ValidationFunc)(o => !string.IsNullOrWhiteSpace(o.Email) || o.AgreeTos), "Please enter the data to update."),
            (AccountAction.Set, (ValidationFunc)(o => !string.IsNullOrWhiteSpace(o.Path)), "Please enter the key file path."),
        };

        public static AccountOptions TryParse(ArgumentSyntax syntax)
        {
            var options = new AccountOptions();

            var command = Command.Undefined;
            syntax.DefineCommand("account", ref command, Command.Account, "Manange ACME account.");
            if (command == Command.Undefined)
            {
                return null;
            }

            syntax.DefineOption("email", ref options.Email, "Email used for registration and recovery contact. (default: None)");
            syntax.DefineOption("agree-tos", ref options.AgreeTos, $"Agree to the ACME Subscriber Agreement. (default: {options.AgreeTos})");

            syntax.DefineOption("server", ref options.Server, s => new Uri(s), $"ACME Directory Resource URI.");
            syntax.DefineOption("key", ref options.Path, $"File path to the account key to use.");

            syntax.DefineParameter(
                "action",
                ref options.Action,
                a => (AccountAction)Enum.Parse(typeof(AccountAction), a?.Replace("-", ""), true),
                "Account action");

            foreach (var validation in validations)
            {
                if (options.Action == validation.Action && !validation.IsValid(options))
                {
                    syntax.ReportError(validation.Help);
                }
            }

            return options;
        }
    }
}