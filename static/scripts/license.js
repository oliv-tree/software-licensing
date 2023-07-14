var password = document.getElementById('password');

function handleStripeJsResult(result) {
  if (result.error) {
    update_status("Card authentication failed");
  } else {
    // The card action has been handled
    // The PaymentIntent can be confirmed again on the server
    fetch('/api/purchase/license', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({payment_intent_id: result.paymentIntent.id, email: email.value, password: password.value, "g-recaptcha-response": grecaptcha.getResponse()})
    }).then(function(confirmResult) {
      return confirmResult.json();
    }).then(handleServerResponse);
  }
}

cardButton.addEventListener('click', function(ev) {
    if (grecaptcha.getResponse() != "" && valid_card && validate_form("license")) {
    cardButton.disabled = true;
    loader.style.display = "inline-block";
    stripe.createPaymentMethod({
      type: 'card',
      card: cardElement
    }).then(function(result) {
      if (result.error) {
        update_status(result.error.message);
      } else {
        // Otherwise send paymentMethod.id to your server (see Step 3)
        fetch('/api/purchase/license', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({payment_method_id: result.paymentMethod.id, email: email.value, password: password.value, "g-recaptcha-response": grecaptcha.getResponse()})
        }).then(function(result) {
          // Handle server response (see Step 3)
          result.json().then(function(json) {
            handleServerResponse(json);
          })
        });
      }
    });
  }
  else {
    // not perfect, says "invalid card details" when it could be more specific
    // will say invalid card details if email/password form not valid!
    update_status("invalid card details")
  }
});

function handleServerResponse(response) {
  if (response.error) {
    update_status(response.error);
  } else if (response.requires_action) {
    // Use Stripe.js to handle required card action
    stripe.handleCardAction(
      response.payment_intent_client_secret
    ).then(handleStripeJsResult);
  } else {
    document.cookie = "password=;"  // clear password cookie
    window.location.href = "http://localhost:5000/status?product=license";

  }
}
