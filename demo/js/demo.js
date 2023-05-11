$(document).ready(function () {
    $(".hamburger").click(function () {
        $(".wrapper").toggleClass("active")
    })
});






//reveal on scroll........

function reveal() {
    var reveals = document.querySelectorAll(".reveal");
  
    for (var i = 0; i < reveals.length; i++) {
      var windowHeight = window.innerHeight;
      var elementTop = reveals[i].getBoundingClientRect().top;
      var elementVisible = 10;
  
      if (elementTop < windowHeight - elementVisible) {
        reveals[i].classList.add("active");
      } else {
        reveals[i].classList.remove("active");
      }
    }
  }
  
  window.addEventListener("scroll", reveal);





//sideclick..................


function displayInfo(infoId) {
  const infoElements = document.querySelectorAll('.script1');
  infoElements.forEach(infoElement => {
    if (infoElement.id === infoId) {
      infoElement.style.display = 'block';   
    } else {
      infoElement.style.display = 'none';
    
    }
  });
}


function displayInfo2(OSId) {
  const OSElements = document.querySelectorAll('.item_wrap');
  OSElements.forEach(OSElement => {
    if (OSElement.id === OSId) {
      OSElement.style.display = 'block';
      alert("okay!");
    } else {
      OSElement.style.display = 'none';
      alert("notokay!");
    }
  });
}


const page = window.location.pathname;
if (page == 'scripts\check-patchinstall.ps1') {
  document.getElementById("CP").style.color = "#B46D6A";
  document.getElementById("CP").style.backgroundColor = "#B46D6A";


}

if (page == '/about_us.html') {
  document.getElementById("about_us").style.color = "#B46D6A";
  
}
if (page == '/contact.html') {
  document.getElementById("navcontact").style.color = "#B46D6A";
}
if (page == '/careers.html') {
  document.getElementById("navcareers").style.color = "#B46D6A";
}




if (window.location.pathname.includes("\check-patchinstall")) {
  document.getElementById("CP").style.backgroundColor = "red";
}

if (window.location.pathname.includes("\clear-softwaredistribution")) {
  document.getElementById("CSD").style.backgroundColor = "red";
}


if (window.location.pathname.includes("\delete_patch_report_task")) {
  document.getElementById("DPR").style.backgroundColor = "red";
}


function copyCode(iframeId) {
  const iframe = document.getElementById(iframeId);
  if (!iframe) {
      console.error("Could not find iframe with ID " + iframeId);
      return;
  }
  const code = iframe.contentDocument.body.innerText;
  if (!navigator.clipboard) {
      console.error("Clipboard API not supported by this browser");
      return;
  }
  navigator.clipboard.writeText(code)
      .then(() => {
          console.log("Code copied to clipboard");
          alert("Code copied to clipboard!");
      })
      .catch((error) => {
          console.error("Failed to copy code: ", error);
          alert("Failed to copy code");
      });
}
