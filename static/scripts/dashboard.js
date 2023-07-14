function swap_page(page_name) {
  var menu_item = document.getElementById(`${page_name}-link`);
  if (menu_item !== null) {
    var current_active = document.getElementsByClassName("active-link")[0];
    current_active.classList.remove("active-link");
    menu_item.classList.add("active-link");
  }

  var page_item = document.getElementById(`${page_name}-sub-content`);
  if (page_item !== null) {
    var current_shown = document.getElementsByClassName("shown")[0];
    current_shown.classList.remove("shown");
    page_item.classList.add("shown");
  }
}
