$('#ip_input').keypress(function (e) {
  if (e.which == 13) {
    $('form#ip_form').submit();
    return false;    //<---- Add this line
  }
});

$('#url_input').keypress(function (e) {
  if (e.which == 13) {
    $('form#url_form').submit();
    return false;    //<---- Add this line
  }
});

$('#hash_input').keypress(function (e) {
  if (e.which == 13) {
    $('form#hash_input').submit();
    return false;    //<---- Add this line
  }
});

$("#comment_btn").click(function(){
    $.post("comment/", $("#comment_f").serialize(), function(data) {
    console.log(type(data))
        });
});