(function(){
buy_button = document.getElementById("buy");
if (in_stock) {
    buy_button.classList.add("in_stock")
    buy_button.innerHTML = "BUY NOW";
    document.getElementById("buy-link").href = "password";
}
else {
  buy_button.classList.remove("in_stock");
  buy_button.innerHTML = "SOLD OUT";
  document.getElementById("buy-link").href = "javascript: void(0)";
}
})();
