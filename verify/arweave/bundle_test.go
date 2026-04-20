package arweave

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
)

const testBundleTxID = "jXN3mTRx5oLuOkfbGxy6DTqw1CS_X25cEJ-ASyrE8is"
const testBundleTxID2 = "sZMocHfDnZ2o5Ziaiv5q6mI_BH_JYBIHbYM7EGFXyKQ"

func TestBundleLightweightMeta(t *testing.T) {
	t.Run("ParseHeaderFromURL", func(t *testing.T) {
		url := fmt.Sprintf("https://arweave.net/raw/%s", testBundleTxID)
		parser, err := ParseBundleHeaderFromURL(url)
		if err != nil {
			t.Fatalf("Failed to parse header from URL: %v", err)
		}

		index := parser.GetIndex()
		fmt.Printf("Bundle %s contains %d items\n", testBundleTxID, index.ItemsNum)
		for i, meta := range index.ItemsMeta {
			fmt.Printf("  Item %d: ID=%s, Length=%d, Offset=%d\n", i, meta.Id, meta.Length, meta.Offset)
		}
	})

	t.Run("FetchTagsFromURL", func(t *testing.T) {
		url := fmt.Sprintf("https://arweave.net/raw/%s", testBundleTxID)
		parser, err := ParseBundleHeaderFromURL(url)
		if err != nil {
			t.Fatalf("Failed to parse header from URL: %v", err)
		}

		index := parser.GetIndex()

		for i := 0; i < index.ItemsNum && i < 3; i++ {
			tags, err := FetchItemTagsFromURL(url, i, parser)
			if err != nil {
				t.Logf("Item %d: failed to fetch tags: %v", i, err)
				continue
			}

			fmt.Printf("Item %d (%s) Tags:\n", i, index.ItemsMeta[i].Id)
			for _, tag := range tags {
				fmt.Printf("  %s: %s\n", tag.Name, tag.Value)
			}
		}
	})
}

func TestBundleParser(t *testing.T) {
	t.Run("ParseHeader", func(t *testing.T) {
		bundleData, err := downloadBundle(testBundleTxID)
		if err != nil {
			t.Skipf("Failed to download bundle (may not be indexed yet): %v", err)
		}
		defer os.Remove(bundleData.Name())

		parser := NewBundleParser(bundleData)
		err = parser.ParseHeader()
		if err != nil {
			t.Fatalf("Failed to parse header: %v", err)
		}

		index := parser.GetIndex()
		if index == nil {
			t.Fatal("Index is nil")
		}

		fmt.Printf("Bundle contains %d items\n", index.ItemsNum)
		for i, meta := range index.ItemsMeta {
			fmt.Printf("  Item %d: ID=%s, Length=%d, Offset=%d\n", i, meta.Id, meta.Length, meta.Offset)
		}
	})

	t.Run("VerifyHeader", func(t *testing.T) {
		bundleData, err := downloadBundle(testBundleTxID)
		if err != nil {
			t.Skipf("Failed to download bundle: %v", err)
		}
		defer os.Remove(bundleData.Name())

		parser := NewBundleParser(bundleData)
		err = parser.ParseHeader()
		if err != nil {
			t.Fatalf("Failed to parse header: %v", err)
		}

		err = parser.VerifyHeader()
		if err != nil {
			t.Fatalf("Header verification failed: %v", err)
		}

		fmt.Println("Header verification passed")
	})

	t.Run("FetchItemTags", func(t *testing.T) {
		bundleData, err := downloadBundle(testBundleTxID)
		if err != nil {
			t.Skipf("Failed to download bundle: %v", err)
		}
		defer os.Remove(bundleData.Name())

		parser := NewBundleParser(bundleData)
		err = parser.ParseHeader()
		if err != nil {
			t.Fatalf("Failed to parse header: %v", err)
		}

		index := parser.GetIndex()
		if index.ItemsNum == 0 {
			t.Fatal("No items in bundle")
		}

		for i := 0; i < index.ItemsNum && i < 3; i++ {
			tags, err := parser.FetchItemTags(i)
			if err != nil {
				t.Logf("Failed to fetch tags for item %d: %v", i, err)
				continue
			}

			fmt.Printf("Item %d Tags:\n", i)
			for _, tag := range tags {
				fmt.Printf("  %s: %s\n", tag.Name, tag.Value)
			}
		}
	})

	t.Run("FetchAndVerifyItem", func(t *testing.T) {
		bundleData, err := downloadBundle(testBundleTxID)
		if err != nil {
			t.Skipf("Failed to download bundle: %v", err)
		}
		defer os.Remove(bundleData.Name())

		parser := NewBundleParser(bundleData)
		err = parser.ParseHeader()
		if err != nil {
			t.Fatalf("Failed to parse header: %v", err)
		}

		index := parser.GetIndex()
		if index.ItemsNum == 0 {
			t.Fatal("No items in bundle")
		}

		itemIndex := 0
		item, err := parser.FetchItem(itemIndex)
		if err != nil {
			t.Fatalf("Failed to fetch item %d: %v", itemIndex, err)
		}

		fmt.Printf("Item %d:\n", itemIndex)
		fmt.Printf("  ID: %s\n", item.Id)
		fmt.Printf("  SignatureType: %d\n", item.SignatureType)
		fmt.Printf("  Owner: %s\n", item.Owner[:20]+"...")
		fmt.Printf("  Tags count: %d\n", len(item.Tags))

		err = parser.VerifyItem(itemIndex)
		if err != nil {
			t.Logf("Item %d verification failed (may be expected): %v", itemIndex, err)
		} else {
			fmt.Printf("Item %d verification passed\n", itemIndex)
		}
	})

	t.Run("ParseAll", func(t *testing.T) {
		bundleData, err := downloadBundle(testBundleTxID)
		if err != nil {
			t.Skipf("Failed to download bundle: %v", err)
		}
		defer os.Remove(bundleData.Name())

		parser := NewBundleParser(bundleData)
		bundle, err := parser.ParseAll()
		if err != nil {
			t.Fatalf("Failed to parse all items: %v", err)
		}

		fmt.Printf("Successfully parsed %d items\n", len(bundle.Items))
	})

	t.Run("ParseBundleFromFile", func(t *testing.T) {
		bundleData, err := downloadBundle(testBundleTxID)
		if err != nil {
			t.Skipf("Failed to download bundle: %v", err)
		}
		filePath := bundleData.Name()
		defer os.Remove(filePath)
		bundleData.Close()

		parser, err := ParseBundleFromFile(filePath)
		if err != nil {
			t.Fatalf("Failed to parse bundle from file: %v", err)
		}
		defer parser.reader.(*os.File).Close()

		index := parser.GetIndex()
		fmt.Printf("Parsed from file: %d items\n", index.ItemsNum)
	})
}

func TestBundleParserWithLocalFile(t *testing.T) {
	localFile := os.Getenv("BUNDLE_TEST_FILE")
	if localFile == "" {
		t.Skip("Set BUNDLE_TEST_FILE environment variable to test with a local file")
	}

	if _, err := os.Stat(localFile); os.IsNotExist(err) {
		t.Fatalf("Local file does not exist: %s", localFile)
	}

	t.Run("ParseHeader", func(t *testing.T) {
		parser, err := ParseBundleFromFile(localFile)
		if err != nil {
			t.Fatalf("Failed to parse bundle: %v", err)
		}
		defer parser.reader.(*os.File).Close()

		index := parser.GetIndex()
		fmt.Printf("Bundle contains %d items\n", index.ItemsNum)
		for i, meta := range index.ItemsMeta {
			fmt.Printf("  Item %d: ID=%s, Length=%d, Offset=%d\n", i, meta.Id, meta.Length, meta.Offset)
		}
	})

	t.Run("FetchItemTags", func(t *testing.T) {
		parser, err := ParseBundleFromFile(localFile)
		if err != nil {
			t.Fatalf("Failed to parse bundle: %v", err)
		}
		defer parser.reader.(*os.File).Close()

		index := parser.GetIndex()
		if index.ItemsNum == 0 {
			t.Fatal("No items in bundle")
		}

		for i := 0; i < index.ItemsNum && i < 3; i++ {
			tags, err := parser.FetchItemTags(i)
			if err != nil {
				t.Logf("Failed to fetch tags for item %d: %v", i, err)
				continue
			}

			fmt.Printf("Item %d Tags:\n", i)
			for _, tag := range tags {
				fmt.Printf("  %s: %s\n", tag.Name, tag.Value)
			}
		}
	})

	t.Run("VerifyItem", func(t *testing.T) {
		parser, err := ParseBundleFromFile(localFile)
		if err != nil {
			t.Fatalf("Failed to parse bundle: %v", err)
		}
		defer parser.reader.(*os.File).Close()

		index := parser.GetIndex()
		if index.ItemsNum == 0 {
			t.Fatal("No items in bundle")
		}

		err = parser.VerifyItem(0)
		if err != nil {
			t.Logf("Item 0 verification: %v", err)
		} else {
			fmt.Println("Item 0 verification passed")
		}
	})
}

func downloadBundle(txID string) (*os.File, error) {
	gateways := []string{
		"https://arweave.net/raw/%s",
		"https://gateway.irys.xyz/%s",
		"https://ar-io.net/raw/%s",
	}

	var lastErr error
	for _, gw := range gateways {
		url := fmt.Sprintf(gw, txID)
		fmt.Printf("Trying gateway %s\n", url)

		resp, err := http.Get(url)
		if err != nil {
			fmt.Printf("Gateway %s failed: %v\n", gw, err)
			lastErr = err
			continue
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			fmt.Printf("Gateway %s returned status: %d\n", gw, resp.StatusCode)
			lastErr = fmt.Errorf("HTTP status: %d", resp.StatusCode)
			continue
		}

		tmpFile, err := os.CreateTemp("", "bundle-*.dat")
		if err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("Create temp file failed: %v", err)
		}

		_, err = io.Copy(tmpFile, resp.Body)
		resp.Body.Close()
		if err != nil {
			tmpFile.Close()
			os.Remove(tmpFile.Name())
			return nil, fmt.Errorf("Download failed: %v", err)
		}

		_, err = tmpFile.Seek(0, 0)
		if err != nil {
			tmpFile.Close()
			os.Remove(tmpFile.Name())
			return nil, fmt.Errorf("Seek failed: %v", err)
		}

		fmt.Printf("Downloaded to %s\n", tmpFile.Name())
		return tmpFile, nil
	}

	return nil, fmt.Errorf("All gateways failed, last error: %v", lastErr)
}
