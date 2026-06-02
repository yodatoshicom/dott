class Dott < Formula
  desc "Private domain search. No middlemen."
  homepage "https://github.com/yodatoshicom/dott"
  version "0.6.8"

  on_macos do
    on_arm do
      url "https://github.com/yodatoshicom/dott/releases/download/v0.6.8/dott-aarch64-apple-darwin.tar.gz"
      sha256 "9d3c7867394c74bbba7ca52540c6b6a42f56bb420e7d6a579f77fe89fafef6e7"
    end
    on_intel do
      url "https://github.com/yodatoshicom/dott/releases/download/v0.6.8/dott-x86_64-apple-darwin.tar.gz"
      sha256 "cf6b396c1330c328b4a2e1efa73909e5453cd0d0eb8cffa0f38000075ce8b320"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/yodatoshicom/dott/releases/download/v0.6.8/dott-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "c0763f9ce8c01122483f961fddf95dede0145b2d20c74b8cc66a83cd0ee26c0a"
    end
    on_intel do
      url "https://github.com/yodatoshicom/dott/releases/download/v0.6.8/dott-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "c94a9e1d2b3f5b43cc3a065396f955c314280a6864d01cf61a43811e368d9567"
    end
  end

  def install
    bin.install "dott"
  end

  test do
    assert_match "dott", shell_output("#{bin}/dott --help")
  end
end
