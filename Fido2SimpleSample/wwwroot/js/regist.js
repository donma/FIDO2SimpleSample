$('#regist').click(async function (event) {

    event.preventDefault();

    var userid = $('#userId').val();
    var userdisplay = $('#userDisplay').val();
    var userpass = $('#userPass').val();



    // prepare form post data
    var data = new FormData();
    data.append('userid', userid);
    data.append('displayName', userdisplay);
    data.append('userpass', userpass);

  
    try {
        res = await registuser(data);
        if (res.status != "ok") {
            showErrorAlert(res.errorMessage);
        } else {
            showSuccess("Regist Success.");
            console.log("Regist Result:" + JSON.stringify(res));
        }
        

    } catch (e) {
        console.error(e);
        let msg = "Something wen't really wrong";
        showErrorAlert(msg);
    }


});


async function registuser(formData) {


    //formData.set('authType', 'platform')
    // formData.set('authType', 'cross-platform');

    let response = await fetch('/api/auth/registuser', {
        method: 'POST', // or 'PUT'
        body: formData, // data can be `string` or {object}!
        headers: {
            'Accept': 'application/json'
        }
    });

    let data = await response.json();

    return data;
}
