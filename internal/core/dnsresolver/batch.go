package dnsresolver

import "context"

type Question struct {
	QName string
	QType uint16
}

type LookupBatchItem struct {
	Question Question
	Result   LookupResult
	Err      error
}

type ResolveBatchItem struct {
	Question Question
	Result   ResolveResult
	Err      error
}

func (r *Resolver) LookupBatch(ctx context.Context, questions []Question) []LookupBatchItem {
	if len(questions) == 0 {
		return nil
	}
	out := make([]LookupBatchItem, 0, len(questions))
	for _, question := range questions {
		result, err := r.Lookup(ctx, question.QName, question.QType)
		out = append(out, LookupBatchItem{
			Question: question,
			Result:   result,
			Err:      err,
		})
	}
	return out
}

func (r *Resolver) ResolveAuthoritativeBatch(
	ctx context.Context,
	servers []AuthoritativeServer,
	opts ResolveOptions,
	questions []Question,
) []ResolveBatchItem {
	if len(questions) == 0 {
		return nil
	}
	out := make([]ResolveBatchItem, 0, len(questions))
	for _, question := range questions {
		result, err := r.ResolveAuthoritative(ctx, question.QName, question.QType, servers, opts)
		out = append(out, ResolveBatchItem{
			Question: question,
			Result:   result,
			Err:      err,
		})
	}
	return out
}
