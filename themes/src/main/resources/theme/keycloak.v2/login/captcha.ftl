<#--
Unified CAPTCHA widget macro that works with any CaptchaProvider.
Supports reCAPTCHA, Turnstile, and any future CAPTCHA implementations.
-->
<#macro captchaWidget>
    <#-- reCAPTCHA v2/v3/Enterprise -->
    <#if recaptchaRequired?? && recaptchaRequired>
        <#if recaptchaVisible!false>
            <#-- reCAPTCHA v2 (visible checkbox) -->
            <div class="form-group">
                <div class="${properties.kcInputWrapperClass!}">
                    <div class="g-recaptcha" data-size="compact" data-sitekey="${recaptchaSiteKey}" data-action="${recaptchaAction}"></div>
                </div>
            </div>
        <#else>
            <#-- reCAPTCHA v3 (invisible) - renders hidden token -->
            <input type="hidden" id="g-recaptcha-response" name="g-recaptcha-response" value="" />
        </#if>
    </#if>

    <#-- Cloudflare Turnstile -->
    <#if turnstileRequired?? && turnstileRequired>
        <div class="form-group">
            <div class="${properties.kcInputWrapperClass!}">
                <div class="cf-turnstile"
                     data-sitekey="${turnstileSiteKey}"
                     data-action="${turnstileAction}"
                     data-theme="${turnstileTheme}"
                     data-size="${turnstileSize}"
                     data-language="${turnstileLanguage}">
                </div>
            </div>
        </div>
    </#if>
</#macro>
