$ErrorActionPreference = "Stop"

Add-Type -AssemblyName System.Drawing

$projectRoot = Split-Path -Parent $PSScriptRoot
$outputPath = Join-Path $projectRoot "assets\dns-shunt.ico"
$sizes = @(16, 24, 32, 48, 64, 128, 256)
$images = [System.Collections.Generic.List[byte[]]]::new()

foreach ($size in $sizes) {
    $bitmap = [System.Drawing.Bitmap]::new(
        $size,
        $size,
        [System.Drawing.Imaging.PixelFormat]::Format32bppArgb
    )
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $graphics.ScaleTransform($size / 512.0, $size / 512.0)
    $graphics.Clear([System.Drawing.Color]::Transparent)

    $tile = [System.Drawing.Drawing2D.GraphicsPath]::new()
    $tile.AddArc(24, 24, 224, 224, 180, 90)
    $tile.AddArc(264, 24, 224, 224, 270, 90)
    $tile.AddArc(264, 264, 224, 224, 0, 90)
    $tile.AddArc(24, 264, 224, 224, 90, 90)
    $tile.CloseFigure()
    $tileBrush = [System.Drawing.SolidBrush]::new(
        [System.Drawing.ColorTranslator]::FromHtml("#111a19")
    )
    $graphics.FillPath($tileBrush, $tile)

    $route = [System.Drawing.Drawing2D.GraphicsPath]::new()
    $route.AddLine(82, 256, 150, 256)
    $route.AddBezier(150, 256, 180, 256, 180, 184, 216, 184)
    $route.AddLine(216, 184, 296, 184)
    $route.AddBezier(296, 184, 332, 184, 332, 256, 362, 256)
    $route.AddLine(362, 256, 392, 256)
    $routePen = [System.Drawing.Pen]::new(
        [System.Drawing.ColorTranslator]::FromHtml("#c9f477"), 22
    )
    $routePen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
    $routePen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
    $routePen.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
    $graphics.DrawPath($routePen, $route)

    $arrow = [System.Drawing.Drawing2D.GraphicsPath]::new()
    $arrow.AddLine(374, 222, 410, 256)
    $arrow.AddLine(410, 256, 374, 290)
    $arrowPen = [System.Drawing.Pen]::new($routePen.Color, 22)
    $arrowPen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
    $arrowPen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
    $arrowPen.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
    $graphics.DrawPath($arrowPen, $arrow)

    $nodeBrush = [System.Drawing.SolidBrush]::new(
        [System.Drawing.ColorTranslator]::FromHtml("#f2a36f")
    )
    $graphics.FillEllipse($nodeBrush, 231, 231, 50, 50)
    $sourceBrush = [System.Drawing.SolidBrush]::new(
        [System.Drawing.ColorTranslator]::FromHtml("#edf4ec")
    )
    $graphics.FillEllipse($sourceBrush, 71, 245, 22, 22)

    $rectangle = [System.Drawing.Rectangle]::new(0, 0, $size, $size)
    $data = $bitmap.LockBits(
        $rectangle,
        [System.Drawing.Imaging.ImageLockMode]::ReadOnly,
        [System.Drawing.Imaging.PixelFormat]::Format32bppArgb
    )
    try {
        $rowBytes = $size * 4
        $pixels = [byte[]]::new($rowBytes * $size)
        $row = [byte[]]::new($rowBytes)
        for ($y = 0; $y -lt $size; $y++) {
            $source = [System.IntPtr]::Add($data.Scan0, $y * $data.Stride)
            [System.Runtime.InteropServices.Marshal]::Copy(
                $source, $row, 0, $rowBytes
            )
            [System.Buffer]::BlockCopy(
                $row, 0, $pixels, ($size - 1 - $y) * $rowBytes, $rowBytes
            )
        }
    }
    finally {
        $bitmap.UnlockBits($data)
    }

    $maskBytes = [int]([Math]::Ceiling($size / 32.0) * 4 * $size)
    $imageStream = [System.IO.MemoryStream]::new()
    $imageWriter = [System.IO.BinaryWriter]::new($imageStream)
    $imageWriter.Write([UInt32]40)
    $imageWriter.Write([Int32]$size)
    $imageWriter.Write([Int32]($size * 2))
    $imageWriter.Write([UInt16]1)
    $imageWriter.Write([UInt16]32)
    $imageWriter.Write([UInt32]0)
    $imageWriter.Write([UInt32]$pixels.Length)
    $imageWriter.Write([Int32]0)
    $imageWriter.Write([Int32]0)
    $imageWriter.Write([UInt32]0)
    $imageWriter.Write([UInt32]0)
    $imageWriter.Write($pixels)
    $imageWriter.Write([byte[]]::new($maskBytes))
    $imageWriter.Flush()
    $images.Add($imageStream.ToArray())

    $imageStream.Dispose()
    $bitmap.Dispose()
    $graphics.Dispose()
    $tile.Dispose()
    $tileBrush.Dispose()
    $route.Dispose()
    $routePen.Dispose()
    $arrow.Dispose()
    $arrowPen.Dispose()
    $nodeBrush.Dispose()
    $sourceBrush.Dispose()
}

$iconStream = [System.IO.MemoryStream]::new()
$iconWriter = [System.IO.BinaryWriter]::new($iconStream)
$iconWriter.Write([UInt16]0)
$iconWriter.Write([UInt16]1)
$iconWriter.Write([UInt16]$sizes.Count)

$offset = 6 + 16 * $sizes.Count
for ($index = 0; $index -lt $sizes.Count; $index++) {
    $size = $sizes[$index]
    $image = $images[$index]
    $dimension = if ($size -eq 256) { 0 } else { $size }
    $iconWriter.Write([byte]$dimension)
    $iconWriter.Write([byte]$dimension)
    $iconWriter.Write([byte]0)
    $iconWriter.Write([byte]0)
    $iconWriter.Write([UInt16]1)
    $iconWriter.Write([UInt16]32)
    $iconWriter.Write([UInt32]$image.Length)
    $iconWriter.Write([UInt32]$offset)
    $offset += $image.Length
}
foreach ($image in $images) {
    $iconWriter.Write($image)
}
$iconWriter.Flush()
[System.IO.File]::WriteAllBytes($outputPath, $iconStream.ToArray())
$iconStream.Dispose()

Write-Output "Generated $outputPath"
