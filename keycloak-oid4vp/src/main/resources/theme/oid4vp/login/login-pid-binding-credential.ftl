<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=true displayInfo=false; section>
    <#if section = "header">
        Issuing Login Credential
    <#elseif section = "form">
        <div id="kc-form">
            <div id="kc-form-wrapper">
                <div class="${properties.kcFormGroupClass!}" style="margin-bottom: 20px;">
                    <div style="background-color: #e8f5e8; border-left: 4px solid #4caf50; padding: 15px; border-radius: 4px;">
                        <h4 style="margin: 0 0 10px 0; color: #2e7d32;">Account Linked Successfully</h4>
                        <p style="margin: 0; color: #1b5e20;">
                            Your German eID has been linked to your account.
                        </p>
                    </div>
                </div>

                <div class="${properties.kcFormGroupClass!}" style="margin-bottom: 20px;">
                    <div style="background-color: #e3f2fd; border-left: 4px solid #2196f3; padding: 15px; border-radius: 4px;">
                        <h4 style="margin: 0 0 10px 0; color: #1565c0;">Issue Login Credential to Your Wallet</h4>
                        <p style="margin: 0 0 15px 0; color: #0d47a1;">
                            A login credential will be issued to your wallet. This credential will allow you to log in directly next time.
                        </p>

                        <#-- Same-device flow: button to open wallet app -->
                        <#if sameDeviceWalletUrl??>
                        <div style="margin-bottom: 15px;">
                            <h5 style="margin: 0 0 10px 0; color: #1565c0;">Same Device</h5>
                            <a href="${sameDeviceWalletUrl}"
                               class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!}"
                               style="display: inline-block; padding: 12px 24px; text-decoration: none; text-align: center; width: 100%;"
                               target="_blank">
                                Open Wallet & Receive Credential
                            </a>
                        </div>
                        </#if>

                        <#-- Cross-device flow: QR code (server-generated) -->
                        <#if qrCodeBase64??>
                        <div style="margin-top: 15px; text-align: center;">
                            <h5 style="margin: 0 0 10px 0; color: #1565c0;">Cross Device (Scan with Wallet)</h5>
                            <img src="data:image/png;base64,${qrCodeBase64}"
                                 alt="QR Code for credential offer"
                                 style="max-width: 200px; border: 1px solid #ddd; padding: 10px; background: white; border-radius: 8px;"/>
                            <p style="margin: 10px 0 0 0; font-size: 0.9em; color: #666;">
                                Scan this QR code with your wallet app
                            </p>
                        </div>
                        </#if>
                        <#-- Fallback: show the URI as text if QR code not available -->
                        <#if openidCredentialOfferUri??>
                        <details style="margin-top: 10px;">
                            <summary style="cursor: pointer; color: #1565c0; font-size: 0.85em;">Show credential offer URI</summary>
                            <textarea readonly style="width: 100%; height: 60px; margin-top: 5px; font-size: 0.75em; font-family: monospace;">${openidCredentialOfferUri}</textarea>
                        </details>
                        </#if>
                    </div>
                </div>

                <form id="kc-form-actions" action="${url.loginAction}" method="post">
                    <div id="kc-form-buttons" class="${properties.kcFormGroupClass!}" style="display: flex; gap: 10px;">
                        <button type="submit" name="continue" value="true"
                                class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!}"
                                style="flex: 1; padding: 12px;">
                            Credential Received - Continue
                        </button>
                        <button type="submit" name="skip" value="true"
                                class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!}"
                                style="flex: 1; padding: 12px;">
                            Skip for Now
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </#if>
</@layout.registrationLayout>
