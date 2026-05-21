class Dott < Formula
  desc "Private domain search. No middlemen."
  homepage "https://github.com/yodatoshicom/dott"
  version "0.6.7"

  on_macos do
    on_arm do
      url "https://github.com/yodatoshicom/dott/releases/download/v0.6.7/dott-aarch64-apple-darwin.tar.gz"
      sha256 "557976c71089194bf7eefc3c5a4710140e5b36d73a4bee296e771bdcfb579b64"
    end
    on_intel do
      url "https://github.com/yodatoshicom/dott/releases/download/v0.6.7/dott-x86_64-apple-darwin.tar.gz"
      sha256 "ab83a3c14ba3f1e2cb56b3ee32ec400261265213aed0fc672c42d181a62106aa"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/yodatoshicom/dott/releases/download/v0.6.7/dott-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "b4db5e4c968e498d9593345077695832551fa55d527127f7c38e18622403e02e"
    end
    on_intel do
      url "https://github.com/yodatoshicom/dott/releases/download/v0.6.7/dott-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "577bc30fffecb6659cd285bb90c13c5d1f0e82327bf506e8d71004658c492832"
    end
  end

  def install
    bin.install "dott"
  end

  test do
    assert_match "dott", shell_output("#{bin}/dott --help")
  end
end
