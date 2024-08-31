# yohacrypt

Bundle encrypter/decrypter for Yohane the Parhelion - NUMAZU in the MIRAGE.

    Usage: yohacrypt [OPTIONS] <PATH>

    Arguments:
      <PATH>

    Options:
      -q, --quiet
      -d, --demo       Use demo key
      -k, --key <KEY>  Use custom key
      -h, --help       Print help
      -V, --version    Print version

# Usage examples

Encrypting/Decrypting single file from demo:

    yohacrypt -d 00000000000000000000000000000000.bundle

Encrypting/Decrypting whole folder from release:

    yohacrypt asset_folder

Encrypting/Decrypting whole folder from another game using custom key:

    yohacrypt -k 'key for another game' another_game_assets

`¶cﾘ˘ヮ˚)|
