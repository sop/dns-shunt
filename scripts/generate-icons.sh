#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  printf 'Usage: %s <source.png>\n' "${0##*/}" >&2
  exit 2
fi

source_image=$1
if [[ ! -f "$source_image" ]]; then
  printf 'Input PNG not found: %s\n' "$source_image" >&2
  exit 1
fi

if command -v magick >/dev/null 2>&1; then
  image_command=(magick)
elif command -v convert >/dev/null 2>&1; then
  image_command=(convert)
else
  printf 'ImageMagick (magick or convert) is required.\n' >&2
  exit 1
fi

if ! command -v identify >/dev/null 2>&1; then
  printf 'ImageMagick identify is required.\n' >&2
  exit 1
fi

project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
assets_dir="$project_root/assets"
temp_dir=$(mktemp -d "$assets_dir/.icons.XXXXXX")
trap 'rm -rf -- "$temp_dir"' EXIT

if [[ $(identify -format '%m' "$source_image") != PNG ]]; then
  printf 'Input must be a PNG image: %s\n' "$source_image" >&2
  exit 1
fi

"${image_command[@]}" "$source_image" -auto-orient -strip \
  -resize '512x512^' \
  -gravity center -background none -extent 512x512 \
  "$temp_dir/master.png"
"${image_command[@]}" "$temp_dir/master.png" -resize 128x128 \
  "$temp_dir/dns-shunt.png"
"${image_command[@]}" "$temp_dir/master.png" \
  -define icon:auto-resize=256,128,64,48,32,24,16 \
  "$temp_dir/dns-shunt.ico"

mv -- "$temp_dir/dns-shunt.png" "$assets_dir/dns-shunt.png"
mv -- "$temp_dir/dns-shunt.ico" "$assets_dir/dns-shunt.ico"
printf 'Generated assets/dns-shunt.png and assets/dns-shunt.ico\n'
