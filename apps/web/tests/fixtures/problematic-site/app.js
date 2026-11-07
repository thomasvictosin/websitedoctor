document.querySelector("#menu-toggle").addEventListener("click", () => {
  throw new Error("The mobile navigation toggle is deliberately broken.");
});

fetch("/missing-api-endpoint").catch(() => {});
fetch("http://169.254.169.254/latest/meta-data").catch(() => {});
