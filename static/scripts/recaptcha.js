var form = document.getElementById('form');
form.addEventListener("submit", function(event){
    if (grecaptcha.getResponse() === '') {
    event.preventDefault();
    message = document.getElementById("message")
    message.innerHTML = "FILL OUT CAPTCHA";
    message.style.display = "block";
    }
}
, false);
