var dropdown = document.getElementsByClassName("dropdown")[0];
var dropdown_width = dropdown.offsetWidth;
var dropdown_content = document.getElementsByClassName("dropdown-content")[0];
console.log(dropdown_width);
dropdown_content.style.width = `${dropdown_width - 50}px`;
