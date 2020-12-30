export class AuthConfig {
    constructor(json) {
        /**
         * The client's id as registered with the auth server
         */
        this.clientId = '';
        /**
         * The client's redirectUri as registered with the auth server
         */
        this.redirectUri = '';
        /**
         * An optional second redirectUri where the auth server
         * redirects the user to after logging out.
         */
        this.postLogoutRedirectUri = '';
        /**
         * The auth server's endpoint that allows to log
         * the user in when using implicit flow.
         */
        this.loginUrl = '';
        /**
         * The requested scopes
         */
        this.scope = 'openid profile';
        this.resource = '';
        this.rngUrl = '';
        /**
         * Defines whether to use OpenId Connect during
         * implicit flow.
         */
        this.oidc = true;
        /**
         * Defines whether to request an access token during
         * implicit flow.
         */
        this.requestAccessToken = true;
        this.options = null;
        /**
         * The issuer's uri.
         */
        this.issuer = '';
        /**
         * The logout url.
         */
        this.logoutUrl = '';
        /**
         * Defines whether to clear the hash fragment after logging in.
         */
        this.clearHashAfterLogin = true;
        /**
         * Url of the token endpoint as defined by OpenId Connect and OAuth 2.
         */
        this.tokenEndpoint = null;
        /**
         * Url of the revocation endpoint as defined by OpenId Connect and OAuth 2.
         */
        this.revocationEndpoint = null;
        /**
         * Names of known parameters sent out in the TokenResponse. https://tools.ietf.org/html/rfc6749#section-5.1
         */
        this.customTokenParameters = [];
        /**
         * Url of the userinfo endpoint as defined by OpenId Connect.
         */
        this.userinfoEndpoint = null;
        this.responseType = '';
        /**
         * Allows to specify where parameters are appended auth request (`query` or `fragment`)
         */
        this.responseMode = '';
        /**
         * Defines whether additional debug information should
         * be shown at the console. Note that in certain browsers
         * the verbosity of the console needs to be explicitly set
         * to include Debug level messages.
         */
        this.showDebugInformation = false;
        /**
         * The redirect uri used when doing silent refresh.
         */
        this.silentRefreshRedirectUri = '';
        this.silentRefreshMessagePrefix = '';
        /**
         * Set this to true to display the iframe used for
         * silent refresh for debugging.
         */
        this.silentRefreshShowIFrame = false;
        /**
         * Timeout for silent refresh.
         * @internal
         * depreacted b/c of typo, see silentRefreshTimeout
         */
        this.siletRefreshTimeout = 1000 * 20;
        /**
         * Timeout for silent refresh.
         */
        this.silentRefreshTimeout = 1000 * 20;
        /**
         * Some auth servers don't allow using password flow
         * w/o a client secret while the standards do not
         * demand for it. In this case, you can set a password
         * here. As this password is exposed to the public
         * it does not bring additional security and is therefore
         * as good as using no password.
         */
        this.dummyClientSecret = null;
        /**
         * Defines whether https is required.
         * The default value is remoteOnly which only allows
         * http for localhost, while every other domains need
         * to be used with https.
         */
        this.requireHttps = 'remoteOnly';
        /**
         * Defines whether every url provided by the discovery
         * document has to start with the issuer's url.
         */
        this.strictDiscoveryDocumentValidation = true;
        /**
         * JSON Web Key Set (https://tools.ietf.org/html/rfc7517)
         * with keys used to validate received id_tokens.
         * This is taken out of the disovery document. Can be set manually too.
         */
        this.jwks = null;
        /**
         * Map with additional query parameter that are appended to
         * the request when initializing implicit flow.
         */
        this.customQueryParams = null;
        this.silentRefreshIFrameName = 'angular-oauth-oidc-silent-refresh-iframe';
        /**
         * Defines when the token_timeout event should be raised.
         * If you set this to the default value 0.75, the event
         * is triggered after 75% of the token's life time.
         */
        this.timeoutFactor = 0.75;
        /**
         * If true, the lib will try to check whether the user
         * is still logged in on a regular basis as described
         * in http://openid.net/specs/openid-connect-session-1_0.html#ChangeNotification
         */
        this.sessionChecksEnabled = false;
        /**
         * Interval in msec for checking the session
         * according to http://openid.net/specs/openid-connect-session-1_0.html#ChangeNotification
         */
        this.sessionCheckIntervall = 3 * 1000;
        /**
         * Url for the iframe used for session checks
         */
        this.sessionCheckIFrameUrl = null;
        /**
         * Name of the iframe to use for session checks
         */
        this.sessionCheckIFrameName = 'angular-oauth-oidc-check-session-iframe';
        /**
         * This property has been introduced to disable at_hash checks
         * and is indented for Identity Provider that does not deliver
         * an at_hash EVEN THOUGH its recommended by the OIDC specs.
         * Of course, when disabling these checks the we are bypassing
         * a security check which means we are more vulnerable.
         */
        this.disableAtHashCheck = false;
        /**
         * Defines wether to check the subject of a refreshed token after silent refresh.
         * Normally, it should be the same as before.
         */
        this.skipSubjectCheck = false;
        this.useIdTokenHintForSilentRefresh = false;
        /**
         * Defined whether to skip the validation of the issuer in the discovery document.
         * Normally, the discovey document's url starts with the url of the issuer.
         */
        this.skipIssuerCheck = false;
        /**
         * final state sent to issuer is built as follows:
         * state = nonce + nonceStateSeparator + additional state
         * Default separator is ';' (encoded %3B).
         * In rare cases, this character might be forbidden or inconvenient to use by the issuer so it can be customized.
         */
        this.nonceStateSeparator = ';';
        /**
         * Set this to true to use HTTP BASIC auth for AJAX calls
         */
        this.useHttpBasicAuth = false;
        /**
         * The interceptors waits this time span if there is no token
         */
        this.waitForTokenInMsec = 0;
        /**
         * Code Flow is by defauld used together with PKCI which is also higly recommented.
         * You can disbale it here by setting this flag to true.
         * https://tools.ietf.org/html/rfc7636#section-1.1
         */
        this.disablePKCE = false;
        /**
         * This property allows you to override the method that is used to open the login url,
         * allowing a way for implementations to specify their own method of routing to new
         * urls.
         */
        this.openUri = uri => {
            location.href = uri;
        };
        if (json) {
            Object.assign(this, json);
        }
    }
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYXV0aC5jb25maWcuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi9wcm9qZWN0cy9saWIvc3JjL2F1dGguY29uZmlnLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBLE1BQU0sT0FBTyxVQUFVO0lBa1FyQixZQUFZLElBQTBCO1FBalF0Qzs7V0FFRztRQUNJLGFBQVEsR0FBSSxFQUFFLENBQUM7UUFFdEI7O1dBRUc7UUFDSSxnQkFBVyxHQUFJLEVBQUUsQ0FBQztRQUV6Qjs7O1dBR0c7UUFDSSwwQkFBcUIsR0FBSSxFQUFFLENBQUM7UUFFbkM7OztXQUdHO1FBQ0ksYUFBUSxHQUFJLEVBQUUsQ0FBQztRQUV0Qjs7V0FFRztRQUNJLFVBQUssR0FBSSxnQkFBZ0IsQ0FBQztRQUUxQixhQUFRLEdBQUksRUFBRSxDQUFDO1FBRWYsV0FBTSxHQUFJLEVBQUUsQ0FBQztRQUVwQjs7O1dBR0c7UUFDSSxTQUFJLEdBQUksSUFBSSxDQUFDO1FBRXBCOzs7V0FHRztRQUNJLHVCQUFrQixHQUFJLElBQUksQ0FBQztRQUUzQixZQUFPLEdBQVMsSUFBSSxDQUFDO1FBRTVCOztXQUVHO1FBQ0ksV0FBTSxHQUFJLEVBQUUsQ0FBQztRQUVwQjs7V0FFRztRQUNJLGNBQVMsR0FBSSxFQUFFLENBQUM7UUFFdkI7O1dBRUc7UUFDSSx3QkFBbUIsR0FBSSxJQUFJLENBQUM7UUFFbkM7O1dBRUc7UUFDSSxrQkFBYSxHQUFZLElBQUksQ0FBQztRQUVyQzs7V0FFRztRQUNJLHVCQUFrQixHQUFZLElBQUksQ0FBQztRQUUxQzs7V0FFRztRQUNJLDBCQUFxQixHQUFjLEVBQUUsQ0FBQztRQUU3Qzs7V0FFRztRQUNJLHFCQUFnQixHQUFZLElBQUksQ0FBQztRQUVqQyxpQkFBWSxHQUFJLEVBQUUsQ0FBQztRQUUxQjs7V0FFRztRQUNJLGlCQUFZLEdBQUksRUFBRSxDQUFDO1FBRTFCOzs7OztXQUtHO1FBQ0kseUJBQW9CLEdBQUksS0FBSyxDQUFDO1FBRXJDOztXQUVHO1FBQ0ksNkJBQXdCLEdBQUksRUFBRSxDQUFDO1FBRS9CLCtCQUEwQixHQUFJLEVBQUUsQ0FBQztRQUV4Qzs7O1dBR0c7UUFDSSw0QkFBdUIsR0FBSSxLQUFLLENBQUM7UUFFeEM7Ozs7V0FJRztRQUNJLHdCQUFtQixHQUFZLElBQUksR0FBRyxFQUFFLENBQUM7UUFFaEQ7O1dBRUc7UUFDSSx5QkFBb0IsR0FBWSxJQUFJLEdBQUcsRUFBRSxDQUFDO1FBRWpEOzs7Ozs7O1dBT0c7UUFDSSxzQkFBaUIsR0FBWSxJQUFJLENBQUM7UUFFekM7Ozs7O1dBS0c7UUFDSSxpQkFBWSxHQUE0QixZQUFZLENBQUM7UUFFNUQ7OztXQUdHO1FBQ0ksc0NBQWlDLEdBQUksSUFBSSxDQUFDO1FBRWpEOzs7O1dBSUc7UUFDSSxTQUFJLEdBQVksSUFBSSxDQUFDO1FBRTVCOzs7V0FHRztRQUNJLHNCQUFpQixHQUFZLElBQUksQ0FBQztRQUVsQyw0QkFBdUIsR0FBSSwwQ0FBMEMsQ0FBQztRQUU3RTs7OztXQUlHO1FBQ0ksa0JBQWEsR0FBSSxJQUFJLENBQUM7UUFFN0I7Ozs7V0FJRztRQUNJLHlCQUFvQixHQUFJLEtBQUssQ0FBQztRQUVyQzs7O1dBR0c7UUFDSSwwQkFBcUIsR0FBSSxDQUFDLEdBQUcsSUFBSSxDQUFDO1FBRXpDOztXQUVHO1FBQ0ksMEJBQXFCLEdBQVksSUFBSSxDQUFDO1FBRTdDOztXQUVHO1FBQ0ksMkJBQXNCLEdBQUkseUNBQXlDLENBQUM7UUFFM0U7Ozs7OztXQU1HO1FBQ0ksdUJBQWtCLEdBQUksS0FBSyxDQUFDO1FBRW5DOzs7V0FHRztRQUNJLHFCQUFnQixHQUFJLEtBQUssQ0FBQztRQUUxQixtQ0FBOEIsR0FBSSxLQUFLLENBQUM7UUFFL0M7OztXQUdHO1FBQ0ksb0JBQWUsR0FBSSxLQUFLLENBQUM7UUFTaEM7Ozs7O1dBS0c7UUFDSSx3QkFBbUIsR0FBSSxHQUFHLENBQUM7UUFFbEM7O1dBRUc7UUFDSSxxQkFBZ0IsR0FBSSxLQUFLLENBQUM7UUFPakM7O1dBRUc7UUFDSSx1QkFBa0IsR0FBSSxDQUFDLENBQUM7UUFVL0I7Ozs7V0FJRztRQUNJLGdCQUFXLEdBQUksS0FBSyxDQUFDO1FBUTVCOzs7O1dBSUc7UUFDSSxZQUFPLEdBQTJCLEdBQUcsQ0FBQyxFQUFFO1lBQzdDLFFBQVEsQ0FBQyxJQUFJLEdBQUcsR0FBRyxDQUFDO1FBQ3RCLENBQUMsQ0FBQztRQVpBLElBQUksSUFBSSxFQUFFO1lBQ1IsTUFBTSxDQUFDLE1BQU0sQ0FBQyxJQUFJLEVBQUUsSUFBSSxDQUFDLENBQUM7U0FDM0I7SUFDSCxDQUFDO0NBVUYiLCJzb3VyY2VzQ29udGVudCI6WyJleHBvcnQgY2xhc3MgQXV0aENvbmZpZyB7XG4gIC8qKlxuICAgKiBUaGUgY2xpZW50J3MgaWQgYXMgcmVnaXN0ZXJlZCB3aXRoIHRoZSBhdXRoIHNlcnZlclxuICAgKi9cbiAgcHVibGljIGNsaWVudElkPyA9ICcnO1xuXG4gIC8qKlxuICAgKiBUaGUgY2xpZW50J3MgcmVkaXJlY3RVcmkgYXMgcmVnaXN0ZXJlZCB3aXRoIHRoZSBhdXRoIHNlcnZlclxuICAgKi9cbiAgcHVibGljIHJlZGlyZWN0VXJpPyA9ICcnO1xuXG4gIC8qKlxuICAgKiBBbiBvcHRpb25hbCBzZWNvbmQgcmVkaXJlY3RVcmkgd2hlcmUgdGhlIGF1dGggc2VydmVyXG4gICAqIHJlZGlyZWN0cyB0aGUgdXNlciB0byBhZnRlciBsb2dnaW5nIG91dC5cbiAgICovXG4gIHB1YmxpYyBwb3N0TG9nb3V0UmVkaXJlY3RVcmk/ID0gJyc7XG5cbiAgLyoqXG4gICAqIFRoZSBhdXRoIHNlcnZlcidzIGVuZHBvaW50IHRoYXQgYWxsb3dzIHRvIGxvZ1xuICAgKiB0aGUgdXNlciBpbiB3aGVuIHVzaW5nIGltcGxpY2l0IGZsb3cuXG4gICAqL1xuICBwdWJsaWMgbG9naW5Vcmw/ID0gJyc7XG5cbiAgLyoqXG4gICAqIFRoZSByZXF1ZXN0ZWQgc2NvcGVzXG4gICAqL1xuICBwdWJsaWMgc2NvcGU/ID0gJ29wZW5pZCBwcm9maWxlJztcblxuICBwdWJsaWMgcmVzb3VyY2U/ID0gJyc7XG5cbiAgcHVibGljIHJuZ1VybD8gPSAnJztcblxuICAvKipcbiAgICogRGVmaW5lcyB3aGV0aGVyIHRvIHVzZSBPcGVuSWQgQ29ubmVjdCBkdXJpbmdcbiAgICogaW1wbGljaXQgZmxvdy5cbiAgICovXG4gIHB1YmxpYyBvaWRjPyA9IHRydWU7XG5cbiAgLyoqXG4gICAqIERlZmluZXMgd2hldGhlciB0byByZXF1ZXN0IGFuIGFjY2VzcyB0b2tlbiBkdXJpbmdcbiAgICogaW1wbGljaXQgZmxvdy5cbiAgICovXG4gIHB1YmxpYyByZXF1ZXN0QWNjZXNzVG9rZW4/ID0gdHJ1ZTtcblxuICBwdWJsaWMgb3B0aW9ucz86IGFueSA9IG51bGw7XG5cbiAgLyoqXG4gICAqIFRoZSBpc3N1ZXIncyB1cmkuXG4gICAqL1xuICBwdWJsaWMgaXNzdWVyPyA9ICcnO1xuXG4gIC8qKlxuICAgKiBUaGUgbG9nb3V0IHVybC5cbiAgICovXG4gIHB1YmxpYyBsb2dvdXRVcmw/ID0gJyc7XG5cbiAgLyoqXG4gICAqIERlZmluZXMgd2hldGhlciB0byBjbGVhciB0aGUgaGFzaCBmcmFnbWVudCBhZnRlciBsb2dnaW5nIGluLlxuICAgKi9cbiAgcHVibGljIGNsZWFySGFzaEFmdGVyTG9naW4/ID0gdHJ1ZTtcblxuICAvKipcbiAgICogVXJsIG9mIHRoZSB0b2tlbiBlbmRwb2ludCBhcyBkZWZpbmVkIGJ5IE9wZW5JZCBDb25uZWN0IGFuZCBPQXV0aCAyLlxuICAgKi9cbiAgcHVibGljIHRva2VuRW5kcG9pbnQ/OiBzdHJpbmcgPSBudWxsO1xuXG4gIC8qKlxuICAgKiBVcmwgb2YgdGhlIHJldm9jYXRpb24gZW5kcG9pbnQgYXMgZGVmaW5lZCBieSBPcGVuSWQgQ29ubmVjdCBhbmQgT0F1dGggMi5cbiAgICovXG4gIHB1YmxpYyByZXZvY2F0aW9uRW5kcG9pbnQ/OiBzdHJpbmcgPSBudWxsO1xuXG4gIC8qKlxuICAgKiBOYW1lcyBvZiBrbm93biBwYXJhbWV0ZXJzIHNlbnQgb3V0IGluIHRoZSBUb2tlblJlc3BvbnNlLiBodHRwczovL3Rvb2xzLmlldGYub3JnL2h0bWwvcmZjNjc0OSNzZWN0aW9uLTUuMVxuICAgKi9cbiAgcHVibGljIGN1c3RvbVRva2VuUGFyYW1ldGVycz86IHN0cmluZ1tdID0gW107XG5cbiAgLyoqXG4gICAqIFVybCBvZiB0aGUgdXNlcmluZm8gZW5kcG9pbnQgYXMgZGVmaW5lZCBieSBPcGVuSWQgQ29ubmVjdC5cbiAgICovXG4gIHB1YmxpYyB1c2VyaW5mb0VuZHBvaW50Pzogc3RyaW5nID0gbnVsbDtcblxuICBwdWJsaWMgcmVzcG9uc2VUeXBlPyA9ICcnO1xuXG4gIC8qKlxuICAgKiBBbGxvd3MgdG8gc3BlY2lmeSB3aGVyZSBwYXJhbWV0ZXJzIGFyZSBhcHBlbmRlZCBhdXRoIHJlcXVlc3QgKGBxdWVyeWAgb3IgYGZyYWdtZW50YClcbiAgICovXG4gIHB1YmxpYyByZXNwb25zZU1vZGU/ID0gJyc7XG5cbiAgLyoqXG4gICAqIERlZmluZXMgd2hldGhlciBhZGRpdGlvbmFsIGRlYnVnIGluZm9ybWF0aW9uIHNob3VsZFxuICAgKiBiZSBzaG93biBhdCB0aGUgY29uc29sZS4gTm90ZSB0aGF0IGluIGNlcnRhaW4gYnJvd3NlcnNcbiAgICogdGhlIHZlcmJvc2l0eSBvZiB0aGUgY29uc29sZSBuZWVkcyB0byBiZSBleHBsaWNpdGx5IHNldFxuICAgKiB0byBpbmNsdWRlIERlYnVnIGxldmVsIG1lc3NhZ2VzLlxuICAgKi9cbiAgcHVibGljIHNob3dEZWJ1Z0luZm9ybWF0aW9uPyA9IGZhbHNlO1xuXG4gIC8qKlxuICAgKiBUaGUgcmVkaXJlY3QgdXJpIHVzZWQgd2hlbiBkb2luZyBzaWxlbnQgcmVmcmVzaC5cbiAgICovXG4gIHB1YmxpYyBzaWxlbnRSZWZyZXNoUmVkaXJlY3RVcmk/ID0gJyc7XG5cbiAgcHVibGljIHNpbGVudFJlZnJlc2hNZXNzYWdlUHJlZml4PyA9ICcnO1xuXG4gIC8qKlxuICAgKiBTZXQgdGhpcyB0byB0cnVlIHRvIGRpc3BsYXkgdGhlIGlmcmFtZSB1c2VkIGZvclxuICAgKiBzaWxlbnQgcmVmcmVzaCBmb3IgZGVidWdnaW5nLlxuICAgKi9cbiAgcHVibGljIHNpbGVudFJlZnJlc2hTaG93SUZyYW1lPyA9IGZhbHNlO1xuXG4gIC8qKlxuICAgKiBUaW1lb3V0IGZvciBzaWxlbnQgcmVmcmVzaC5cbiAgICogQGludGVybmFsXG4gICAqIGRlcHJlYWN0ZWQgYi9jIG9mIHR5cG8sIHNlZSBzaWxlbnRSZWZyZXNoVGltZW91dFxuICAgKi9cbiAgcHVibGljIHNpbGV0UmVmcmVzaFRpbWVvdXQ/OiBudW1iZXIgPSAxMDAwICogMjA7XG5cbiAgLyoqXG4gICAqIFRpbWVvdXQgZm9yIHNpbGVudCByZWZyZXNoLlxuICAgKi9cbiAgcHVibGljIHNpbGVudFJlZnJlc2hUaW1lb3V0PzogbnVtYmVyID0gMTAwMCAqIDIwO1xuXG4gIC8qKlxuICAgKiBTb21lIGF1dGggc2VydmVycyBkb24ndCBhbGxvdyB1c2luZyBwYXNzd29yZCBmbG93XG4gICAqIHcvbyBhIGNsaWVudCBzZWNyZXQgd2hpbGUgdGhlIHN0YW5kYXJkcyBkbyBub3RcbiAgICogZGVtYW5kIGZvciBpdC4gSW4gdGhpcyBjYXNlLCB5b3UgY2FuIHNldCBhIHBhc3N3b3JkXG4gICAqIGhlcmUuIEFzIHRoaXMgcGFzc3dvcmQgaXMgZXhwb3NlZCB0byB0aGUgcHVibGljXG4gICAqIGl0IGRvZXMgbm90IGJyaW5nIGFkZGl0aW9uYWwgc2VjdXJpdHkgYW5kIGlzIHRoZXJlZm9yZVxuICAgKiBhcyBnb29kIGFzIHVzaW5nIG5vIHBhc3N3b3JkLlxuICAgKi9cbiAgcHVibGljIGR1bW15Q2xpZW50U2VjcmV0Pzogc3RyaW5nID0gbnVsbDtcblxuICAvKipcbiAgICogRGVmaW5lcyB3aGV0aGVyIGh0dHBzIGlzIHJlcXVpcmVkLlxuICAgKiBUaGUgZGVmYXVsdCB2YWx1ZSBpcyByZW1vdGVPbmx5IHdoaWNoIG9ubHkgYWxsb3dzXG4gICAqIGh0dHAgZm9yIGxvY2FsaG9zdCwgd2hpbGUgZXZlcnkgb3RoZXIgZG9tYWlucyBuZWVkXG4gICAqIHRvIGJlIHVzZWQgd2l0aCBodHRwcy5cbiAgICovXG4gIHB1YmxpYyByZXF1aXJlSHR0cHM/OiBib29sZWFuIHwgJ3JlbW90ZU9ubHknID0gJ3JlbW90ZU9ubHknO1xuXG4gIC8qKlxuICAgKiBEZWZpbmVzIHdoZXRoZXIgZXZlcnkgdXJsIHByb3ZpZGVkIGJ5IHRoZSBkaXNjb3ZlcnlcbiAgICogZG9jdW1lbnQgaGFzIHRvIHN0YXJ0IHdpdGggdGhlIGlzc3VlcidzIHVybC5cbiAgICovXG4gIHB1YmxpYyBzdHJpY3REaXNjb3ZlcnlEb2N1bWVudFZhbGlkYXRpb24/ID0gdHJ1ZTtcblxuICAvKipcbiAgICogSlNPTiBXZWIgS2V5IFNldCAoaHR0cHM6Ly90b29scy5pZXRmLm9yZy9odG1sL3JmYzc1MTcpXG4gICAqIHdpdGgga2V5cyB1c2VkIHRvIHZhbGlkYXRlIHJlY2VpdmVkIGlkX3Rva2Vucy5cbiAgICogVGhpcyBpcyB0YWtlbiBvdXQgb2YgdGhlIGRpc292ZXJ5IGRvY3VtZW50LiBDYW4gYmUgc2V0IG1hbnVhbGx5IHRvby5cbiAgICovXG4gIHB1YmxpYyBqd2tzPzogb2JqZWN0ID0gbnVsbDtcblxuICAvKipcbiAgICogTWFwIHdpdGggYWRkaXRpb25hbCBxdWVyeSBwYXJhbWV0ZXIgdGhhdCBhcmUgYXBwZW5kZWQgdG9cbiAgICogdGhlIHJlcXVlc3Qgd2hlbiBpbml0aWFsaXppbmcgaW1wbGljaXQgZmxvdy5cbiAgICovXG4gIHB1YmxpYyBjdXN0b21RdWVyeVBhcmFtcz86IG9iamVjdCA9IG51bGw7XG5cbiAgcHVibGljIHNpbGVudFJlZnJlc2hJRnJhbWVOYW1lPyA9ICdhbmd1bGFyLW9hdXRoLW9pZGMtc2lsZW50LXJlZnJlc2gtaWZyYW1lJztcblxuICAvKipcbiAgICogRGVmaW5lcyB3aGVuIHRoZSB0b2tlbl90aW1lb3V0IGV2ZW50IHNob3VsZCBiZSByYWlzZWQuXG4gICAqIElmIHlvdSBzZXQgdGhpcyB0byB0aGUgZGVmYXVsdCB2YWx1ZSAwLjc1LCB0aGUgZXZlbnRcbiAgICogaXMgdHJpZ2dlcmVkIGFmdGVyIDc1JSBvZiB0aGUgdG9rZW4ncyBsaWZlIHRpbWUuXG4gICAqL1xuICBwdWJsaWMgdGltZW91dEZhY3Rvcj8gPSAwLjc1O1xuXG4gIC8qKlxuICAgKiBJZiB0cnVlLCB0aGUgbGliIHdpbGwgdHJ5IHRvIGNoZWNrIHdoZXRoZXIgdGhlIHVzZXJcbiAgICogaXMgc3RpbGwgbG9nZ2VkIGluIG9uIGEgcmVndWxhciBiYXNpcyBhcyBkZXNjcmliZWRcbiAgICogaW4gaHR0cDovL29wZW5pZC5uZXQvc3BlY3Mvb3BlbmlkLWNvbm5lY3Qtc2Vzc2lvbi0xXzAuaHRtbCNDaGFuZ2VOb3RpZmljYXRpb25cbiAgICovXG4gIHB1YmxpYyBzZXNzaW9uQ2hlY2tzRW5hYmxlZD8gPSBmYWxzZTtcblxuICAvKipcbiAgICogSW50ZXJ2YWwgaW4gbXNlYyBmb3IgY2hlY2tpbmcgdGhlIHNlc3Npb25cbiAgICogYWNjb3JkaW5nIHRvIGh0dHA6Ly9vcGVuaWQubmV0L3NwZWNzL29wZW5pZC1jb25uZWN0LXNlc3Npb24tMV8wLmh0bWwjQ2hhbmdlTm90aWZpY2F0aW9uXG4gICAqL1xuICBwdWJsaWMgc2Vzc2lvbkNoZWNrSW50ZXJ2YWxsPyA9IDMgKiAxMDAwO1xuXG4gIC8qKlxuICAgKiBVcmwgZm9yIHRoZSBpZnJhbWUgdXNlZCBmb3Igc2Vzc2lvbiBjaGVja3NcbiAgICovXG4gIHB1YmxpYyBzZXNzaW9uQ2hlY2tJRnJhbWVVcmw/OiBzdHJpbmcgPSBudWxsO1xuXG4gIC8qKlxuICAgKiBOYW1lIG9mIHRoZSBpZnJhbWUgdG8gdXNlIGZvciBzZXNzaW9uIGNoZWNrc1xuICAgKi9cbiAgcHVibGljIHNlc3Npb25DaGVja0lGcmFtZU5hbWU/ID0gJ2FuZ3VsYXItb2F1dGgtb2lkYy1jaGVjay1zZXNzaW9uLWlmcmFtZSc7XG5cbiAgLyoqXG4gICAqIFRoaXMgcHJvcGVydHkgaGFzIGJlZW4gaW50cm9kdWNlZCB0byBkaXNhYmxlIGF0X2hhc2ggY2hlY2tzXG4gICAqIGFuZCBpcyBpbmRlbnRlZCBmb3IgSWRlbnRpdHkgUHJvdmlkZXIgdGhhdCBkb2VzIG5vdCBkZWxpdmVyXG4gICAqIGFuIGF0X2hhc2ggRVZFTiBUSE9VR0ggaXRzIHJlY29tbWVuZGVkIGJ5IHRoZSBPSURDIHNwZWNzLlxuICAgKiBPZiBjb3Vyc2UsIHdoZW4gZGlzYWJsaW5nIHRoZXNlIGNoZWNrcyB0aGUgd2UgYXJlIGJ5cGFzc2luZ1xuICAgKiBhIHNlY3VyaXR5IGNoZWNrIHdoaWNoIG1lYW5zIHdlIGFyZSBtb3JlIHZ1bG5lcmFibGUuXG4gICAqL1xuICBwdWJsaWMgZGlzYWJsZUF0SGFzaENoZWNrPyA9IGZhbHNlO1xuXG4gIC8qKlxuICAgKiBEZWZpbmVzIHdldGhlciB0byBjaGVjayB0aGUgc3ViamVjdCBvZiBhIHJlZnJlc2hlZCB0b2tlbiBhZnRlciBzaWxlbnQgcmVmcmVzaC5cbiAgICogTm9ybWFsbHksIGl0IHNob3VsZCBiZSB0aGUgc2FtZSBhcyBiZWZvcmUuXG4gICAqL1xuICBwdWJsaWMgc2tpcFN1YmplY3RDaGVjaz8gPSBmYWxzZTtcblxuICBwdWJsaWMgdXNlSWRUb2tlbkhpbnRGb3JTaWxlbnRSZWZyZXNoPyA9IGZhbHNlO1xuXG4gIC8qKlxuICAgKiBEZWZpbmVkIHdoZXRoZXIgdG8gc2tpcCB0aGUgdmFsaWRhdGlvbiBvZiB0aGUgaXNzdWVyIGluIHRoZSBkaXNjb3ZlcnkgZG9jdW1lbnQuXG4gICAqIE5vcm1hbGx5LCB0aGUgZGlzY292ZXkgZG9jdW1lbnQncyB1cmwgc3RhcnRzIHdpdGggdGhlIHVybCBvZiB0aGUgaXNzdWVyLlxuICAgKi9cbiAgcHVibGljIHNraXBJc3N1ZXJDaGVjaz8gPSBmYWxzZTtcblxuICAvKipcbiAgICogQWNjb3JkaW5nIHRvIHJmYzY3NDkgaXQgaXMgcmVjb21tZW5kZWQgKGJ1dCBub3QgcmVxdWlyZWQpIHRoYXQgdGhlIGF1dGhcbiAgICogc2VydmVyIGV4cG9zZXMgdGhlIGFjY2Vzc190b2tlbidzIGxpZmUgdGltZSBpbiBzZWNvbmRzLlxuICAgKiBUaGlzIGlzIGEgZmFsbGJhY2sgdmFsdWUgZm9yIHRoZSBjYXNlIHRoaXMgdmFsdWUgaXMgbm90IGV4cG9zZWQuXG4gICAqL1xuICBwdWJsaWMgZmFsbGJhY2tBY2Nlc3NUb2tlbkV4cGlyYXRpb25UaW1lSW5TZWM/OiBudW1iZXI7XG5cbiAgLyoqXG4gICAqIGZpbmFsIHN0YXRlIHNlbnQgdG8gaXNzdWVyIGlzIGJ1aWx0IGFzIGZvbGxvd3M6XG4gICAqIHN0YXRlID0gbm9uY2UgKyBub25jZVN0YXRlU2VwYXJhdG9yICsgYWRkaXRpb25hbCBzdGF0ZVxuICAgKiBEZWZhdWx0IHNlcGFyYXRvciBpcyAnOycgKGVuY29kZWQgJTNCKS5cbiAgICogSW4gcmFyZSBjYXNlcywgdGhpcyBjaGFyYWN0ZXIgbWlnaHQgYmUgZm9yYmlkZGVuIG9yIGluY29udmVuaWVudCB0byB1c2UgYnkgdGhlIGlzc3VlciBzbyBpdCBjYW4gYmUgY3VzdG9taXplZC5cbiAgICovXG4gIHB1YmxpYyBub25jZVN0YXRlU2VwYXJhdG9yPyA9ICc7JztcblxuICAvKipcbiAgICogU2V0IHRoaXMgdG8gdHJ1ZSB0byB1c2UgSFRUUCBCQVNJQyBhdXRoIGZvciBBSkFYIGNhbGxzXG4gICAqL1xuICBwdWJsaWMgdXNlSHR0cEJhc2ljQXV0aD8gPSBmYWxzZTtcblxuICAvKipcbiAgICogVGhlIHdpbmRvdyBvZiB0aW1lIChpbiBzZWNvbmRzKSB0byBhbGxvdyB0aGUgY3VycmVudCB0aW1lIHRvIGRldmlhdGUgd2hlbiB2YWxpZGF0aW5nIGlkX3Rva2VuJ3MgaWF0IGFuZCBleHAgdmFsdWVzLlxuICAgKi9cbiAgcHVibGljIGNsb2NrU2tld0luU2VjPzogbnVtYmVyO1xuXG4gIC8qKlxuICAgKiBUaGUgaW50ZXJjZXB0b3JzIHdhaXRzIHRoaXMgdGltZSBzcGFuIGlmIHRoZXJlIGlzIG5vIHRva2VuXG4gICAqL1xuICBwdWJsaWMgd2FpdEZvclRva2VuSW5Nc2VjPyA9IDA7XG5cbiAgLyoqXG4gICAqIFNldCB0aGlzIHRvIHRydWUgaWYgeW91IHdhbnQgdG8gdXNlIHNpbGVudCByZWZyZXNoIHRvZ2V0aGVyIHdpdGhcbiAgICogY29kZSBmbG93LiBBcyBzaWxlbnQgcmVmcmVzaCBpcyB0aGUgb25seSBvcHRpb24gZm9yIHJlZnJlc2hpbmdcbiAgICogd2l0aCBpbXBsaWNpdCBmbG93LCB5b3UgZG9uJ3QgbmVlZCB0byBleHBsaWNpdGx5IHR1cm4gaXQgb24gaW5cbiAgICogdGhpcyBjYXNlLlxuICAgKi9cbiAgcHVibGljIHVzZVNpbGVudFJlZnJlc2g/O1xuXG4gIC8qKlxuICAgKiBDb2RlIEZsb3cgaXMgYnkgZGVmYXVsZCB1c2VkIHRvZ2V0aGVyIHdpdGggUEtDSSB3aGljaCBpcyBhbHNvIGhpZ2x5IHJlY29tbWVudGVkLlxuICAgKiBZb3UgY2FuIGRpc2JhbGUgaXQgaGVyZSBieSBzZXR0aW5nIHRoaXMgZmxhZyB0byB0cnVlLlxuICAgKiBodHRwczovL3Rvb2xzLmlldGYub3JnL2h0bWwvcmZjNzYzNiNzZWN0aW9uLTEuMVxuICAgKi9cbiAgcHVibGljIGRpc2FibGVQS0NFPyA9IGZhbHNlO1xuXG4gIGNvbnN0cnVjdG9yKGpzb24/OiBQYXJ0aWFsPEF1dGhDb25maWc+KSB7XG4gICAgaWYgKGpzb24pIHtcbiAgICAgIE9iamVjdC5hc3NpZ24odGhpcywganNvbik7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICAqIFRoaXMgcHJvcGVydHkgYWxsb3dzIHlvdSB0byBvdmVycmlkZSB0aGUgbWV0aG9kIHRoYXQgaXMgdXNlZCB0byBvcGVuIHRoZSBsb2dpbiB1cmwsXG4gICAqIGFsbG93aW5nIGEgd2F5IGZvciBpbXBsZW1lbnRhdGlvbnMgdG8gc3BlY2lmeSB0aGVpciBvd24gbWV0aG9kIG9mIHJvdXRpbmcgdG8gbmV3XG4gICAqIHVybHMuXG4gICAqL1xuICBwdWJsaWMgb3BlblVyaT86ICh1cmk6IHN0cmluZykgPT4gdm9pZCA9IHVyaSA9PiB7XG4gICAgbG9jYXRpb24uaHJlZiA9IHVyaTtcbiAgfTtcbn1cbiJdfQ==