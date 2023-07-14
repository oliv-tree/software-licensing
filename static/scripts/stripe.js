var stripe = Stripe(''); // TODO: get from credentials.json

var elements = stripe.elements({fonts:[{"cssSrc": "https://fonts.googleapis.com/css?family=Source+Sans+Pro:400,600,700"}],});
// Set up Stripe.js and Elements to use in checkout form
var style = {
  base: {
    color: "#fff",
    fontFamily: '"Source Sans Pro", sans-serif',
    textTransform: "uppercase",
    fontSize: '12px',
    iconColor: "#bbb",
    lineHeight: "37px",
    letterSpacing: "2px",
    '::placeholder': {
      color: '#bbb',
      fontFamily: '"Source Sans Pro", sans-serif',
      letterSpacing: "2px",
    },
    '::selection': {
      color: '#fff',
      backgroundColor: '#333',
    }
  }
};

var cardElement = elements.create('card', {style: style});
cardElement.mount('#card-element');

var email = document.getElementById('email');
var cardButton = document.getElementById('card-button');
var loader = document.getElementById('loader');
var purchase_form = document.getElementById("form-form");
var valid_captcha = false;
var valid_card = false;

function update_status(message) {
  var status = document.getElementById("message");
  status.innerHTML = message.split('.').join("");
  cardButton.disabled = false;
  loader.style.display = "none";
}


function validate_form(product) {
  valid = false;
  if (product == "license") {
    if (email.checkValidity() && password.checkValidity()) {
      valid = true;
    }
  }
  else {
    if (email.checkValidity()) {
      valid = true;
    }
  }
  return valid;
}


cardElement.addEventListener('change', function(event) {
  if (event.error) {
    valid_card = false,
    update_status(event.error.message);
  }
  else {
    valid_card = true;
    if (status.innerHTML != "FILL OUT CAPTCHA") {  // more !=
        status.innerHTML = "";
    }
  }
});
