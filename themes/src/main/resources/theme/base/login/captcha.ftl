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

<#--
Submit button that handles reCAPTCHA v3 (invisible) properly.
For reCAPTCHA v3, the button must trigger the CAPTCHA challenge before form submission.
For other CAPTCHA types or no CAPTCHA, renders a standard submit button.

reCAPTCHA v3 workflow:
1. User clicks button → reCAPTCHA generates token asynchronously
2. data-callback is invoked with token → onSubmitRecaptcha() called
3. onSubmitRecaptcha() submits the form with the token
Without this callback, the form would submit before the token is generated and validation would fail.

Parameters:
  - formId: The ID of the form to submit (required for reCAPTCHA v3 callback)
  - label: The button label/value
  - class: Additional CSS classes (optional)
  - id: Button ID (optional, defaults to derived from formId)
  - name: Button name attribute (optional)
-->
<#macro captchaSubmitButton formId label class="" id="" name="">
    <#-- reCAPTCHA v3 (invisible) requires special button handling -->
    <#if recaptchaRequired?? && recaptchaRequired && !(recaptchaVisible!false)>
        <script>
            function onSubmitRecaptcha(token) {
                document.getElementById("${formId}").requestSubmit();
            }
        </script>
        <button
            class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!} g-recaptcha<#if class?has_content> ${class}</#if>"
            data-sitekey="${recaptchaSiteKey}"
            data-callback='onSubmitRecaptcha'
            data-action='${recaptchaAction}'
            type="submit"
            <#if id?has_content>id="${id}"</#if>
            <#if name?has_content>name="${name}"</#if>>
            ${label}
        </button>
    <#else>
        <#-- Standard submit button for reCAPTCHA v2, Turnstile, or no CAPTCHA -->
        <input
            class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}<#if class?has_content> ${class}</#if>"
            type="submit"
            value="${label}"
            <#if id?has_content>id="${id}"</#if>
            <#if name?has_content>name="${name}"</#if>/>
    </#if>
</#macro>
