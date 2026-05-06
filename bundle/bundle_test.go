package bundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"
)

func TestBundleBuilder(t *testing.T) {
	t.Run("CreateAndBuildWithRSA", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}

		item := NewDataItem()
		item.AddTag("Content-Type", "text/plain")
		item.AddTag("App-Name", "TestApp")
		item.SetData([]byte("Hello, Arweave!"))
		item.SetAnchor([]byte("test-anchor-value-123456789012"))

		if err := item.SignWithRSA(privateKey); err != nil {
			t.Fatalf("Failed to sign item: %v", err)
		}

		builder := NewBundleBuilder()
		builder.AddItem(item)

		if builder.ItemCount() != 1 {
			t.Errorf("Expected 1 item, got %d", builder.ItemCount())
		}

		data, err := builder.Build()
		if err != nil {
			t.Fatalf("Failed to build bundle: %v", err)
		}

		fmt.Printf("✓ RSA 签名捆绑包构建成功\n")
		fmt.Printf("  数据项数量: %d\n", builder.ItemCount())
		fmt.Printf("  捆绑包大小: %d bytes\n", len(data))
		fmt.Printf("  数据项 ID: %x\n", item.Id[:8])

		if len(data) == 0 {
			t.Fatal("Bundle data is empty")
		}

		if err := builder.VerifyAll(); err != nil {
			t.Fatalf("Bundle verification failed: %v", err)
		}
		fmt.Printf("✓ 捆绑包验证通过\n")
	})

	t.Run("CreateAndBuildWithEd25519", func(t *testing.T) {
		pubKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate Ed25519 key: %v", err)
		}

		item := NewDataItem()
		item.SetSignatureType(ED25519SignType)
		item.SetOwner(pubKey)
		item.AddTag("Content-Type", "application/json")
		item.SetData([]byte(`{"message":"Hello"}`))

		if err := item.SignWithEd25519(privateKey); err != nil {
			t.Fatalf("Failed to sign item: %v", err)
		}

		builder := NewBundleBuilder()
		builder.AddItem(item)

		data, err := builder.Build()
		if err != nil {
			t.Fatalf("Failed to build bundle: %v", err)
		}

		fmt.Printf("✓ Ed25519 签名捆绑包构建成功\n")
		fmt.Printf("  捆绑包大小: %d bytes\n", len(data))

		if err := builder.VerifyAll(); err != nil {
			t.Fatalf("Bundle verification failed: %v", err)
		}
		fmt.Printf("✓ Ed25519 捆绑包验证通过\n")
	})

	t.Run("MultipleItems", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}

		builder := NewBundleBuilder()

		for i := 0; i < 5; i++ {
			item := NewDataItem()
			item.AddTag("Index", fmt.Sprintf("%d", i))
			item.SetData([]byte(fmt.Sprintf("Data item %d", i)))

			if err := item.SignWithRSA(privateKey); err != nil {
				t.Fatalf("Failed to sign item %d: %v", i, err)
			}

			builder.AddItem(item)
		}

		if builder.ItemCount() != 5 {
			t.Errorf("Expected 5 items, got %d", builder.ItemCount())
		}

		data, err := builder.Build()
		if err != nil {
			t.Fatalf("Failed to build bundle: %v", err)
		}

		fmt.Printf("✓ 多数据项捆绑包构建成功\n")
		fmt.Printf("  数据项数量: %d\n", builder.ItemCount())
		fmt.Printf("  捆绑包大小: %d bytes\n", len(data))

		if err := builder.VerifyAll(); err != nil {
			t.Fatalf("Bundle verification failed: %v", err)
		}
	})
}

func TestBundleParsing(t *testing.T) {
	t.Run("ParseBuiltBundle", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}

		builder := NewBundleBuilder()

		for i := 0; i < 3; i++ {
			item := NewDataItem()
			item.AddTag("Key", fmt.Sprintf("Value%d", i))
			item.SetData([]byte(fmt.Sprintf("Test data %d", i)))

			if err := item.SignWithRSA(privateKey); err != nil {
				t.Fatalf("Failed to sign item %d: %v", i, err)
			}

			builder.AddItem(item)
		}

		data, err := builder.Build()
		if err != nil {
			t.Fatalf("Failed to build bundle: %v", err)
		}

		bundle, err := ParseBundle(data)
		if err != nil {
			t.Fatalf("Failed to parse bundle: %v", err)
		}

		if len(bundle.Items) != 3 {
			t.Errorf("Expected 3 items, got %d", len(bundle.Items))
		}

		fmt.Printf("✓ 捆绑包解析成功\n")
		fmt.Printf("  解析数据项数: %d\n", len(bundle.Items))

		for i, item := range bundle.Items {
			fmt.Printf("  数据项 %d: ID=%x, 数据=%d bytes, 标签=%d\n",
				i, item.Id[:8], len(item.Data), len(item.Tags))

			if string(item.Data) != fmt.Sprintf("Test data %d", i) {
				t.Errorf("Item %d data mismatch", i)
			}
		}
	})
}

func TestBundleRoundTrip(t *testing.T) {
	t.Run("BuildAndParseMatch", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}

		originalItems := make([]DataItem, 0, 3)
		builder := NewBundleBuilder()

		for i := 0; i < 3; i++ {
			item := NewDataItem()
			item.AddTag("Name", fmt.Sprintf("Item%d", i))
			item.AddTag("Value", fmt.Sprintf("Data%d", i))
			item.SetData([]byte(fmt.Sprintf("Content %d", i)))

			if err := item.SignWithRSA(privateKey); err != nil {
				t.Fatalf("Failed to sign item %d: %v", i, err)
			}

			originalItems = append(originalItems, item)
			builder.AddItem(item)
		}

		data, err := builder.Build()
		if err != nil {
			t.Fatalf("Failed to build bundle: %v", err)
		}

		bundle, err := ParseBundle(data)
		if err != nil {
			t.Fatalf("Failed to parse bundle: %v", err)
		}

		if len(bundle.Items) != len(originalItems) {
			t.Fatalf("Item count mismatch: expected %d, got %d", len(originalItems), len(bundle.Items))
		}

		for i, parsedItem := range bundle.Items {
			original := originalItems[i]

			if parsedItem.SignatureType != original.SignatureType {
				t.Errorf("Item %d: signature type mismatch", i)
			}

			if !bytes.Equal(parsedItem.Data, original.Data) {
				t.Errorf("Item %d: data mismatch", i)
			}

			if len(parsedItem.Tags) != len(original.Tags) {
				t.Errorf("Item %d: tag count mismatch: expected %d, got %d",
					i, len(original.Tags), len(parsedItem.Tags))
			}

			for j, tag := range parsedItem.Tags {
				if tag.Name != original.Tags[j].Name || tag.Value != original.Tags[j].Value {
					t.Errorf("Item %d, tag %d: tag mismatch", i, j)
				}
			}
		}

		fmt.Printf("✓ 构建-解析往返测试通过\n")
	})
}

func TestBundleValidation(t *testing.T) {
	t.Run("EmptyBundle", func(t *testing.T) {
		builder := NewBundleBuilder()

		_, err := builder.Build()
		if err == nil {
			t.Fatal("Expected error for empty bundle")
		}

		fmt.Printf("✓ 空捆绑包检测正确: %v\n", err)
	})

	t.Run("UnsignedItem", func(t *testing.T) {
		builder := NewBundleBuilder()

		item := NewDataItem()
		item.AddTag("Test", "Value")
		item.SetData([]byte("test"))

		builder.AddItem(item)

		_, err := builder.Build()
		if err == nil {
			t.Fatal("Expected error for unsigned item")
		}

		fmt.Printf("✓ 未签名数据项检测正确: %v\n", err)
	})

	t.Run("InvalidSignature", func(t *testing.T) {
		builder := NewBundleBuilder()

		item := NewDataItem()
		item.SignatureType = ArweaveSignType
		item.Signature = make([]byte, 512)
		item.Owner = make([]byte, 512)
		item.Id = make([]byte, 32)
		item.AddTag("Test", "Value")
		item.SetData([]byte("test"))

		builder.AddItem(item)

		if err := builder.VerifyAll(); err == nil {
			t.Fatal("Expected error for invalid signature")
		}

		fmt.Printf("✓ 无效签名检测正确\n")
	})
}

func TestBundleToWriter(t *testing.T) {
	t.Run("BuildToBuffer", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}

		builder := NewBundleBuilder()

		item := NewDataItem()
		item.AddTag("Content-Type", "text/plain")
		item.SetData([]byte("Hello, World!"))

		if err := item.SignWithRSA(privateKey); err != nil {
			t.Fatalf("Failed to sign item: %v", err)
		}

		builder.AddItem(item)

		var buf bytes.Buffer
		if err := builder.BuildToWriter(&buf); err != nil {
			t.Fatalf("Failed to build to writer: %v", err)
		}

		if buf.Len() == 0 {
			t.Fatal("Buffer is empty")
		}

		fmt.Printf("✓ 写入 Buffer 成功\n")
		fmt.Printf("  写入大小: %d bytes\n", buf.Len())

		bundle, err := ParseBundle(buf.Bytes())
		if err != nil {
			t.Fatalf("Failed to parse bundle from buffer: %v", err)
		}

		if len(bundle.Items) != 1 {
			t.Errorf("Expected 1 item, got %d", len(bundle.Items))
		}
	})
}

func TestBundleClear(t *testing.T) {
	t.Run("ClearAndReuse", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}

		builder := NewBundleBuilder()

		item := NewDataItem()
		item.AddTag("Test", "Value")
		item.SetData([]byte("test"))
		item.SignWithRSA(privateKey)
		builder.AddItem(item)

		if builder.ItemCount() != 1 {
			t.Fatalf("Expected 1 item, got %d", builder.ItemCount())
		}

		builder.Clear()

		if builder.ItemCount() != 0 {
			t.Fatalf("Expected 0 items after clear, got %d", builder.ItemCount())
		}

		item2 := NewDataItem()
		item2.AddTag("Test2", "Value2")
		item2.SetData([]byte("test2"))
		item2.SignWithRSA(privateKey)
		builder.AddItem(item2)

		if builder.ItemCount() != 1 {
			t.Fatalf("Expected 1 item after adding new, got %d", builder.ItemCount())
		}

		fmt.Printf("✓ 清空和重用构建器成功\n")
	})
}

func TestBundleGetItems(t *testing.T) {
	t.Run("GetItems", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}

		builder := NewBundleBuilder()

		item := NewDataItem()
		item.AddTag("Test", "Value")
		item.SetData([]byte("test"))
		item.SignWithRSA(privateKey)
		builder.AddItem(item)

		items := builder.GetItems()
		if len(items) != 1 {
			t.Fatalf("Expected 1 item, got %d", len(items))
		}

		if len(items[0].Data) != 4 {
			t.Fatalf("Expected data length 4, got %d", len(items[0].Data))
		}

		fmt.Printf("✓ 获取数据项列表成功\n")
	})
}
